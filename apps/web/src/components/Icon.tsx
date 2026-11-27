// Иконки — IBM Carbon (@carbon/icons-react), 16/20 px сетка. Декоративные иконки скрыты от AT (aria-hidden);
// если у иконки есть смысл без соседнего текста — передайте label.
import {
  Activity,
  Add,
  ArrowsHorizontal,
  Asleep,
  Book,
  Catalog,
  Checkmark,
  CheckmarkFilled,
  Chip,
  Close,
  Collaborate,
  Currency,
  Dashboard,
  DataBase,
  DocumentTasks,
  ErrorFilled,
  Filter,
  Information,
  InformationFilled,
  InProgress,
  Launch,
  Light,
  Locked,
  Logout,
  Menu,
  Misuse,
  Network_3,
  Pending,
  Plug,
  Renew,
  Reset,
  Search,
  Security,
  Settings,
  StopFilledAlt,
  Subtract,
  WarningAlt,
  WarningAltFilled,
  WarningFilled,
  type CarbonIconType,
} from "@carbon/icons-react";

const ICONS: Record<string, CarbonIconType> = {
  // навигация
  dashboard: Dashboard,
  alert: WarningAlt,
  agents: Collaborate,
  changes: ArrowsHorizontal,
  server: DataBase,
  topology: Network_3,
  book: Book,
  shield: Security,
  cpu: Chip,
  audit: DocumentTasks,
  heart: Activity,
  settings: Settings,
  catalog: Catalog,
  // действия
  menu: Menu,
  x: Close,
  sun: Light,
  moon: Asleep,
  logout: Logout,
  plus: Add,
  refresh: Renew,
  reset: Reset,
  search: Search,
  filter: Filter,
  launch: Launch,
  // состояние
  check: Checkmark,
  minus: Subtract,
  info: Information,
  warning: WarningAlt,
  stop: StopFilledAlt,
  lock: Locked,
  plug: Plug,
  money: Currency,
  // семантические статусы (Carbon status icons: цвет + форма)
  "st-success": CheckmarkFilled,
  "st-info": InformationFilled,
  "st-warning": WarningAltFilled,
  "st-danger": ErrorFilled,
  "st-critical": WarningFilled,
  "st-progress": InProgress,
  "st-pending": Pending,
  "st-neutral": Misuse,
};

export type IconName = keyof typeof ICONS;

export function Icon({ name, size = 16, className, label }: { name: IconName | string; size?: 16 | 20 | 24 | 32 | number; className?: string; label?: string }) {
  const C = ICONS[name] ?? Information;
  return (
    <C
      className={className}
      size={size}
      aria-hidden={label ? undefined : true}
      aria-label={label}
      role={label ? "img" : undefined}
      focusable="false"
    />
  );
}

/** Фирменный знак AdminTwin (сохранён без изменений формы, цвет — от токена акцента). */
export function LogoMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <rect x="1" y="1" width="30" height="30" rx="7" fill="var(--brand)" />
      <path d="M9 22 15 9l6 13M11.5 17h7" stroke="#ffffff" strokeWidth="2.4" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="24" cy="10" r="2.4" fill="#ffffff" />
    </svg>
  );
}
