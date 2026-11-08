import { Icon } from '../lib/Icon'

export function Header({ search, onSearch }) {
  return (
    <header className="flex h-[88px] w-full shrink-0 items-center gap-4 bg-background px-4 pt-4 pb-2">
      <div className="flex h-14 shrink-0 items-center gap-3 rounded-[32px] bg-layer py-1 pr-6 pl-1">
        <div className="flex size-12 items-center justify-center rounded-3xl bg-inverse">
          <Icon name="brand-shield" className="size-5" />
        </div>
        <p className="text-base leading-6 font-semibold whitespace-nowrap text-text-primary">Before the Breach</p>
      </div>

      <label className="flex h-14 w-[520px] shrink-0 items-center gap-2.5 rounded-full bg-layer px-5">
        <Icon name="search-target" className="size-[18px]" />
        <input
          type="search"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search CVEs, vendors, charts or SHE issues"
          className="type-body-compact w-full bg-transparent text-text-primary outline-none placeholder:text-text-secondary"
        />
      </label>

      <div className="h-px min-w-px flex-1" />

      <button
        type="button"
        className="type-body-compact flex h-14 shrink-0 cursor-pointer items-center rounded-full bg-primary px-6 font-semibold whitespace-nowrap text-white hover:bg-primary-strong"
      >
        + Import SBOM
      </button>
      <button type="button" aria-label="Notifications" className="cursor-pointer rounded-full">
        <Icon name="button-notifications" className="size-14" />
      </button>
      <div className="flex size-14 shrink-0 items-center justify-center rounded-[28px] bg-primary text-xl leading-7 text-white">
        M
      </div>
    </header>
  )
}
