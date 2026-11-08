// Downloads the SVG assets used by the Fix-First queue page (Figma node 55:454)
// into public/icons/. Run once: `npm run fetch-assets`.
// Figma's MCP asset URLs expire about 7 days after they were generated (Nov 7, 2026).
// If they have expired, re-run get_design_context on the frame to get fresh URLs.
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const PREFIX = 'https://www.figma.com/api/mcp/asset/2d1dd177-b2b4-4c24-944b-19539e533af0'

// local file name -> Figma asset id
const ASSETS = {
  'brand-shield': '0b6f4',
  'search-target': 'd2c56',
  'button-notifications': '7ccc8',
  'nav-arrow': 'c259f',
  'nav-queue': 'e7a37',
  'nav-bell': '669b2',
  'nav-target': '45bf3',
  'icon-upload': '313a1',
  'icon-idea': 'dcd85',
  'deco-ring-1': '1b2d2',
  'deco-ring-2': 'a5fce',
  'deco-dot': 'cdeff',
  'icon-ticket-white': '318aa',
  'icon-arrow-up-right': 'b48bf',
  'icon-shield': 'cd42c',
  'gauge-67': 'd1df6',
  'icon-arrow-up-red': 'a154c',
  'hatch-1': 'b72c8',
  'hatch-2': 'be1f8',
  'hatch-3': 'b942d',
  'hatch-4': 'b3d43',
  'hatch-5': '18406',
  'icon-search': 'a0354',
  'icon-filter': '07155',
  'status-critical': 'ad03e',
  'status-high': '3f48b',
  'chevron-down': 'e1564',
  'chevron-down-white': '1bd61',
  'chevron-down-lg': '9f6cf',
  'icon-check': '70037',
  'icon-ticket': '371f7',
  'icon-copy': '211bb',
  'icon-close': 'ca99f',
  'arrow-up-white': 'd1f4a',
  'arrow-up-blue': 'af72f',
  'hatch-cvss-card': '648b8',
  'rank-ellipse': 'f2637',
  'icon-code': '06e7c',
  'hatch-bar': '0b04b',
  'icon-shield-sm': 'b93ff',
  'icon-vendor': 'e516a',
  'icon-idea-dark': '9bf61',
  'icon-launch': 'b30a2',
}

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'icons')
await mkdir(outDir, { recursive: true })

let failed = 0
await Promise.all(
  Object.entries(ASSETS).map(async ([name, id]) => {
    try {
      const res = await fetch(`${PREFIX}/${id}.svg`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const body = await res.text()
      if (!body.trim()) throw new Error('empty file')
      await writeFile(join(outDir, `${name}.svg`), body)
      console.log(`✓ ${name}.svg`)
    } catch (err) {
      failed++
      console.error(`✗ ${name}.svg (${id}): ${err.message}`)
    }
  }),
)

console.log(failed ? `\n${failed} asset(s) failed.` : `\nAll ${Object.keys(ASSETS).length} assets saved to public/icons/`)
process.exitCode = failed ? 1 : 0
