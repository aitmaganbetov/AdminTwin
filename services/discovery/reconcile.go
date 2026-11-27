package discovery

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/services/inventory"
)

func assetKey(typ, name string) string { return typ + "|" + strings.ToLower(strings.TrimSpace(name)) }

func addrKey(typ, addr string) string { return typ + "|" + addr }

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// normalize приводит наблюдение к виду CMDB: tenant, источник discovery, без атрибутов классификации.
// Discovery никогда не выставляет environment/criticality/owner/data_class — это решение человека (§8.3).
func normalize(tenantID string, t TargetInput, idx int, a inventory.Asset, sc *Scope) (inventory.Asset, []string) {
	var warns []string
	out := inventory.Asset{
		TenantID: tenantID, Name: strings.TrimSpace(a.Name), Type: strings.TrimSpace(a.Type), Objects: a.Objects,
		Reachability: "reachable", Source: "discovery", HealthEndpoint: "",
	}
	if a.Connection != nil {
		c := *a.Connection
		out.Connection = &c
	}
	if idx == 0 {
		// Основной объект цели: подключение — из задания (адрес уже проверен по scope).
		out.Connection = &inventory.Connection{Method: t.Method, Address: t.Address, Port: t.Port, CredentialRef: t.CredentialRef, HostKey: t.HostKey, TLSServerName: t.TLSServerName}
	} else if out.Connection != nil {
		ip, err := netip.ParseAddr(out.Connection.Address)
		if err != nil || sc == nil || !sc.Contains(ip) {
			warns = append(warns, "connection address outside scope dropped")
			out.Connection = nil
		} else if out.Connection.CredentialRef != t.CredentialRef {
			out.Connection.CredentialRef = "" // ссылку на учётку задаёт только задание
		}
	}
	if out.Connection != nil {
		out.Connection.TLSSkipVerify = false
	}
	return out, warns
}

// reconcile сопоставляет наблюдения с CMDB: new / changed / missing / unchanged, с оценкой confidence.
func (s *Service) reconcile(sc *Scope, results []collected) []Finding {
	tenantID := sc.TenantID
	existing := s.inv.List(tenantID)
	byKey, byAddr := map[string]inventory.Asset{}, map[string]inventory.Asset{}
	for _, a := range existing {
		byKey[assetKey(a.Type, a.Name)] = a
		if a.Connection != nil && a.Connection.Address != "" {
			byAddr[addrKey(a.Type, a.Connection.Address)] = a
		}
	}
	var findings []Finding
	seen := map[string]bool{}    // ключи наблюдений
	matched := map[string]bool{} // id активов CMDB, сопоставленных в этом задании
	for _, r := range results {
		if r.err != nil {
			continue
		}
		for i, raw := range r.obs.Assets {
			a, warns := normalize(tenantID, r.target, i, raw, sc)
			conf := r.obs.Confidence
			if a.Type == "" {
				continue // объект без типа не сопоставляется
			}
			if a.Name == "" {
				a.Name = r.target.Address
				conf *= 0.5
				warns = append(warns, "name not reported; address used")
			}
			conf -= 0.05 * float64(len(r.obs.Warnings)+len(warns))
			conf = round3(math.Max(0, math.Min(1, conf)))
			key := assetKey(a.Type, a.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			f := Finding{Key: key, Name: a.Name, Type: a.Type, Method: r.target.Method, Confidence: conf, observed: a, Warnings: append(append([]string(nil), r.obs.Warnings...), warns...)}
			if a.Connection != nil {
				f.Address = a.Connection.Address
			}
			var cur inventory.Asset
			found, byName := false, false
			if a.Connection != nil {
				cur, found = byAddr[addrKey(a.Type, a.Connection.Address)]
			}
			if !found {
				cur, found = byKey[key]
				byName = found
			}
			if found {
				matched[cur.ID] = true
				f.AssetID = cur.ID
				f.Diff = diff(cur, a)
				if len(f.Diff) == 0 {
					f.Change = FindingUnchanged
				} else {
					f.Change = FindingChanged
				}
				f.ClassificationIncomplete = len(cur.ClassificationComplete()) > 0
			} else {
				f.Change = FindingNew
				f.ClassificationIncomplete = true
			}
			f.NeedsConfirmation = (f.Change == FindingNew || f.Change == FindingChanged) && conf < s.cfg.ConfirmThreshold
			if found && (connectionDiffers(cur.Connection, a.Connection) || (byName && a.Connection != nil)) {
				// Имя сообщает сам сканируемый хост; адрес/учётные данные существующего актива меняет только
				// Tenant Admin (не автор задания) — иначе можно перенаправить production-актив на подставной хост.
				f.ConnectionChange, f.RequiresAdmin, f.NeedsConfirmation = true, true, true
				if f.Change == FindingUnchanged {
					f.Change = FindingChanged
				}
				f.Diff = append(f.Diff, "connection")
				f.Warnings = append(f.Warnings, "connection parameters of an existing asset differ or asset matched by self-reported name only")
			}
			for _, d := range r.obs.Dependencies {
				if d.SourceName == raw.Name {
					f.deps = append(f.deps, d)
				}
			}
			findings = append(findings, f)
		}
	}
	// missing: активы CMDB с подключением к успешно опрошенной цели (тем же методом), не найденные в задании.
	for _, r := range results {
		if r.err != nil {
			continue
		}
		for _, a := range existing {
			if matched[a.ID] || a.Connection == nil || a.Connection.Address != r.target.Address || a.Connection.Method != r.target.Method {
				continue
			}
			key := assetKey(a.Type, a.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, Finding{Key: key, Change: FindingMissing, AssetID: a.ID, Name: a.Name, Type: a.Type, Address: a.Connection.Address, Method: a.Connection.Method, Confidence: round3(r.obs.Confidence), ClassificationIncomplete: len(a.ClassificationComplete()) > 0})
		}
	}
	if findings == nil {
		findings = []Finding{}
	}
	sortFindings(findings)
	return findings
}

func diff(cur, obs inventory.Asset) []string {
	var d []string
	if cur.Name != obs.Name {
		d = append(d, fmt.Sprintf("name: %q -> %q", cur.Name, obs.Name))
	}
	if !objectsEqual(cur.Objects, obs.Objects) {
		d = append(d, "objects changed")
	}
	cc, oc := cur.Connection, obs.Connection
	switch {
	case cc == nil && oc != nil:
		d = append(d, "connection added")
	case cc != nil && oc != nil:
		if cc.Method != oc.Method || cc.Address != oc.Address || (oc.Port != 0 && cc.Port != oc.Port) {
			d = append(d, fmt.Sprintf("connection: %s://%s:%d -> %s://%s:%d", cc.Method, cc.Address, cc.Port, oc.Method, oc.Address, oc.Port))
		}
		if oc.HostKey != "" && cc.HostKey != oc.HostKey {
			d = append(d, "host key changed")
		}
	}
	if cur.Reachability == "unreachable" {
		d = append(d, "reachability: unreachable -> reachable")
	}
	return d
}

func objectsEqual(a, b map[string][]string) bool {
	norm := func(m map[string][]string) map[string][]string {
		out := map[string][]string{}
		for k, v := range m {
			if len(v) == 0 {
				continue
			}
			cp := append([]string(nil), v...)
			sort.Strings(cp)
			out[k] = cp
		}
		return out
	}
	na, nb := norm(a), norm(b)
	if len(na) != len(nb) {
		return false
	}
	for k, v := range na {
		if !slices.Equal(v, nb[k]) {
			return false
		}
	}
	return true
}

// applyConfident применяет к CMDB находки с достаточным confidence.
func (s *Service) applyConfident(job *Job) {
	changed := false
	for i := range job.Findings {
		f := &job.Findings[i]
		if f.NeedsConfirmation || (f.Change != FindingNew && f.Change != FindingChanged) {
			continue
		}
		if err := s.apply(job.TenantID, f, false); err != nil { // автоприменение никогда не меняет подключение
			f.Warnings = append(f.Warnings, "apply failed: "+truncate(err.Error(), 200))
			continue
		}
		changed = true
	}
	// Связи — после записи всех объектов (оба конца должны существовать в CMDB).
	s.applyAllDeps(job)
	if changed && s.OnCMDBChange != nil {
		s.OnCMDBChange()
	}
}

// apply записывает находку в CMDB, сохраняя атрибуты классификации существующего актива.
func (s *Service) apply(tenantID string, f *Finding, allowConnection bool) error {
	obs := f.observed
	switch f.Change {
	case FindingNew:
		obs.ID = newID()
		if err := s.inv.Put(obs); err != nil {
			return err
		}
		f.AssetID = obs.ID
	case FindingChanged:
		cur, ok := s.inv.Get(tenantID, f.AssetID)
		if !ok {
			return fmt.Errorf("asset disappeared from CMDB")
		}
		upd := *cur
		upd.Name = obs.Name
		if obs.Objects != nil {
			upd.Objects = obs.Objects
		}
		if obs.Connection != nil && (allowConnection || cur.Connection == nil) {
			c := *obs.Connection
			if c.CredentialRef == "" && cur.Connection != nil {
				c.CredentialRef = cur.Connection.CredentialRef
			}
			if c.HostKey == "" && cur.Connection != nil {
				c.HostKey = cur.Connection.HostKey
			}
			upd.Connection = &c
		}
		upd.Reachability = "reachable"
		// Environment, Criticality, DataClass, Owner, LegalHold, Verified — не меняются discovery.
		if err := s.inv.Put(upd); err != nil {
			return err
		}
	default:
		return nil
	}
	f.Applied = true
	return nil
}

func (s *Service) applyAllDeps(job *Job) {
	for i := range job.Findings {
		if job.Findings[i].Applied {
			s.applyDeps(job.TenantID, &job.Findings[i])
		}
	}
}

func (s *Service) applyDeps(tenantID string, f *Finding) {
	if len(f.deps) == 0 {
		return
	}
	byName := map[string]string{}
	for _, a := range s.inv.List(tenantID) {
		byName[strings.ToLower(a.Name)] = a.ID
	}
	have := map[string]bool{}
	for _, d := range s.inv.Dependencies(tenantID) {
		have[d.Source+"|"+d.Target+"|"+d.RelationType] = true
	}
	for _, d := range f.deps {
		src, dst := byName[strings.ToLower(d.SourceName)], byName[strings.ToLower(d.TargetName)]
		if src == "" || dst == "" || src == dst || d.RelationType == "" {
			continue
		}
		if have[src+"|"+dst+"|"+d.RelationType] {
			continue
		}
		conf := d.Confidence
		if conf <= 0 || conf > 1 {
			conf = 0.5
		}
		_ = s.inv.AddDependency(inventory.Dependency{TenantID: tenantID, Source: src, Target: dst, RelationType: d.RelationType, Confidence: round3(conf), VerifiedBy: "discovery", DiscoveredAt: time.Now().UTC()})
	}
}

// connectionDiffers — изменились ли параметры подключения существующего актива.
func connectionDiffers(cur, obs *inventory.Connection) bool {
	if obs == nil {
		return false
	}
	if cur == nil {
		return false // у актива ещё не было подключения: задаётся при первом обнаружении
	}
	return cur.Address != obs.Address || (obs.Port != 0 && cur.Port != obs.Port) ||
		(obs.CredentialRef != "" && cur.CredentialRef != obs.CredentialRef) ||
		(obs.HostKey != "" && cur.HostKey != obs.HostKey) ||
		(obs.TLSServerName != "" && cur.TLSServerName != obs.TLSServerName) || cur.Method != obs.Method
}
