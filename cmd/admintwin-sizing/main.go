// Command admintwin-sizing — калькулятор объёмов хранения для первичного планирования (ТЗ §9.1).
//
// Ориентир ТЗ на 1000 активов: метрики ~150–250 ГБ/год, логи ~1–3 ТБ/год, flows ~2–5 ТБ/год raw,
// аудит ~20 ГБ/год. Это ориентир, не SLA: окончательный sizing — по фактической cardinality,
// ingestion, compression, HA и replay (стенд нагрузочного тестирования, ADR-009).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
)

// Input — параметры площадки.
type Input struct {
	Assets               int     `json:"assets"`
	SeriesPerAsset       int     `json:"series_per_asset"`       // активные временные ряды на актив
	ScrapeIntervalS      int     `json:"scrape_interval_s"`      // интервал сбора метрик
	BytesPerSample       float64 `json:"bytes_per_sample"`       // после сжатия (VictoriaMetrics ~0.4–1 байт)
	LogMBPerAssetDay     float64 `json:"log_mb_per_asset_day"`   // сырые журналы
	LogCompression       float64 `json:"log_compression"`        // коэффициент сжатия журналов
	FlowsPerSecond       float64 `json:"flows_per_second"`       // NetFlow/IPFIX (P1a); 0 — не собираются
	BytesPerFlow         float64 `json:"bytes_per_flow"`         // после сжатия в ClickHouse
	AuditEventsPerDay    float64 `json:"audit_events_per_day"`   // записи аудита
	BytesPerAuditEvent   float64 `json:"bytes_per_audit_event"`  //
	ReplicationFactor    float64 `json:"replication_factor"`     // HA: копий данных
	RawMetricRetentionD  int     `json:"raw_metric_retention_d"` // §9.1: 15
	Metric5mRetentionD   int     `json:"metric_5m_retention_d"`  // 90
	Metric1hRetentionD   int     `json:"metric_1h_retention_d"`  // 730
	LogHotRetentionD     int     `json:"log_hot_retention_d"`    // 14
	LogTotalRetentionD   int     `json:"log_total_retention_d"`  // 90
	FlowRawRetentionD    int     `json:"flow_raw_retention_d"`   // 7
	FlowAggRetentionD    int     `json:"flow_agg_retention_d"`   // 365
	AuditRetentionD      int     `json:"audit_retention_d"`      // 3 года
	FlowAggregationRatio float64 `json:"flow_aggregation_ratio"` // во сколько раз агрегаты меньше raw
}

// Defaults — значения по умолчанию из §9.1 и типичные коэффициенты.
func Defaults() Input {
	return Input{Assets: 1000, SeriesPerAsset: 200, ScrapeIntervalS: 30, BytesPerSample: 0.9,
		LogMBPerAssetDay: 40, LogCompression: 10, FlowsPerSecond: 0, BytesPerFlow: 25,
		AuditEventsPerDay: 50000, BytesPerAuditEvent: 1100, ReplicationFactor: 1,
		RawMetricRetentionD: 15, Metric5mRetentionD: 90, Metric1hRetentionD: 730,
		LogHotRetentionD: 14, LogTotalRetentionD: 90, FlowRawRetentionD: 7, FlowAggRetentionD: 365,
		AuditRetentionD: 1095, FlowAggregationRatio: 20}
}

// Line — строка отчёта.
type Line struct {
	Kind      string  `json:"kind"`
	Tier      string  `json:"tier"`
	GB        float64 `json:"gb"`
	PerYearGB float64 `json:"per_year_gb"`
	Note      string  `json:"note,omitempty"`
}

// Report — результат расчёта.
type Report struct {
	Input   Input   `json:"input"`
	Lines   []Line  `json:"lines"`
	TotalGB float64 `json:"total_gb"`
	Ingest  struct {
		SamplesPerSec float64 `json:"samples_per_sec"`
		LogMBPerSec   float64 `json:"log_mb_per_sec"`
		FlowsPerSec   float64 `json:"flows_per_sec"`
	} `json:"ingest"`
	Warnings []string `json:"warnings,omitempty"`
}

const gb = 1e9

// Compute рассчитывает объёмы.
func Compute(in Input) (Report, error) {
	if in.Assets <= 0 || in.ScrapeIntervalS <= 0 || in.SeriesPerAsset <= 0 || in.LogCompression <= 0 || in.ReplicationFactor < 1 {
		return Report{}, fmt.Errorf("assets, series_per_asset, scrape_interval_s, log_compression must be positive; replication_factor >= 1")
	}
	r := Report{Input: in}
	series := float64(in.Assets * in.SeriesPerAsset)
	samplesPerSec := series / float64(in.ScrapeIntervalS)
	r.Ingest.SamplesPerSec = samplesPerSec
	day := 86400.0
	rawPerDay := samplesPerSec * day * in.BytesPerSample / gb
	m5PerDay := series * (day / 300) * in.BytesPerSample * 1.5 / gb // агрегаты хранят min/max/avg
	m1hPerDay := series * 24 * in.BytesPerSample * 1.5 / gb
	add := func(kind, tier string, perDay float64, days int, note string) {
		v := perDay * float64(days) * in.ReplicationFactor
		r.Lines = append(r.Lines, Line{Kind: kind, Tier: tier, GB: round(v), PerYearGB: round(perDay * 365 * in.ReplicationFactor), Note: note})
		r.TotalGB += v
	}
	add("metrics raw", "hot", rawPerDay, in.RawMetricRetentionD, "downsampling после окна")
	add("metrics 5m", "hot", m5PerDay, in.Metric5mRetentionD, "")
	add("metrics 1h", "hot+MinIO", m1hPerDay, in.Metric1hRetentionD, "")

	logRaw := float64(in.Assets) * in.LogMBPerAssetDay / 1000 // ГБ/день сырых
	r.Ingest.LogMBPerSec = logRaw * 1000 / day
	logStored := logRaw / in.LogCompression
	add("logs", "hot", logStored, in.LogHotRetentionD, "ПДн — §18.3")
	if in.LogTotalRetentionD > in.LogHotRetentionD {
		add("logs", "cold (MinIO)", logStored, in.LogTotalRetentionD-in.LogHotRetentionD, "")
	}
	if logRaw*30 > 500 {
		r.Warnings = append(r.Warnings, "журналы > 500 ГБ/мес: по §3.5 рекомендуется ClickHouse вместо Loki (ADR-002)")
	}
	if in.FlowsPerSecond > 0 {
		r.Ingest.FlowsPerSec = in.FlowsPerSecond
		flowRaw := in.FlowsPerSecond * day * in.BytesPerFlow / gb
		add("flows raw", "ClickHouse", flowRaw, in.FlowRawRetentionD, "самый тяжёлый поток; отдельный sizing")
		add("flows aggregates", "ClickHouse/MinIO", flowRaw/in.FlowAggregationRatio, in.FlowAggRetentionD, "")
		if in.FlowsPerSecond > 20000 {
			r.Warnings = append(r.Warnings, "flows > 20k/с превышают целевой показатель §17.1 для одного коллектора: требуется горизонтальное масштабирование")
		}
	}
	auditPerDay := in.AuditEventsPerDay * in.BytesPerAuditEvent / gb
	add("audit", "БД 13 мес + WORM", auditPerDay, in.AuditRetentionD, "hash chain; WORM Object Lock")
	if samplesPerSec > 50000 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("ingestion метрик %.0f samples/с выше целевого 50k/с (§17.1): нужен кластер хранилища метрик", samplesPerSec))
	}
	if r.Ingest.LogMBPerSec > 20 {
		r.Warnings = append(r.Warnings, "ingestion логов выше целевого 20 МБ/с (§17.1)")
	}
	r.TotalGB = round(r.TotalGB)
	return r, nil
}

func round(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

func main() {
	in := Defaults()
	cfgPath := flag.String("config", "", "JSON с параметрами (см. -print-defaults)")
	printDefaults := flag.Bool("print-defaults", false, "вывести параметры по умолчанию")
	asJSON := flag.Bool("json", false, "вывод в JSON")
	flag.IntVar(&in.Assets, "assets", in.Assets, "число активов")
	flag.Float64Var(&in.FlowsPerSecond, "flows", in.FlowsPerSecond, "NetFlow/IPFIX flows/с (0 — без flows)")
	flag.Float64Var(&in.ReplicationFactor, "replicas", in.ReplicationFactor, "копий данных (HA)")
	flag.Parse()
	if *printDefaults {
		_ = json.NewEncoder(os.Stdout).Encode(Defaults())
		return
	}
	if *cfgPath != "" {
		raw, err := os.ReadFile(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
	}
	rep, err := Compute(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		return
	}
	print(os.Stdout, rep)
}

func print(w io.Writer, r Report) {
	fmt.Fprintf(w, "AdminTwin sizing: %d активов, %.0f samples/с, %.2f МБ/с журналов, %.0f flows/с\n\n",
		r.Input.Assets, r.Ingest.SamplesPerSec, r.Ingest.LogMBPerSec, r.Ingest.FlowsPerSec)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Данные\tУровень\tОбъём, ГБ\tГБ/год\tПримечание")
	for _, l := range r.Lines {
		fmt.Fprintf(tw, "%s\t%s\t%.1f\t%.1f\t%s\n", l.Kind, l.Tier, l.GB, l.PerYearGB, l.Note)
	}
	fmt.Fprintf(tw, "ИТОГО\t\t%.1f\t\t\n", r.TotalGB)
	tw.Flush()
	for _, wn := range r.Warnings {
		fmt.Fprintln(w, "ВНИМАНИЕ:", wn)
	}
	fmt.Fprintln(w, "\nОриентир для первичного планирования, не SLA (§9.1). Окончательный sizing — по нагрузочным тестам (ADR-009).")
}
