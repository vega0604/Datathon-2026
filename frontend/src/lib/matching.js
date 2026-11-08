// How the backend matched a component's CVEs (API `match_methods` per component).
// `_product_only`: the product matched NIST's list but the vendor didn't (weaker).
const METHOD = {
  cpe: 'CPE name',
  cpe_product_only: 'CPE product',
  purl: 'package URL',
  purl_product_only: 'package name',
  name: 'name',
  name_product_only: 'product name',
  description: 'CVE text',
}
const ORDER = Object.keys(METHOD)

/** Methods matched against NIST's product list other than an exact CPE name. */
export const byProductList = (methods) => methods.filter((m) => m !== 'cpe' && m !== 'description')

/** Methods in a fixed order; for data without them, inferred from the CPE name. */
export function matchMethods(component) {
  const m = component.matchMethods?.length ? component.matchMethods : component.cpe ? ['cpe'] : []
  return ORDER.filter((k) => m.includes(k))
}

/** "CPE name", "package URL and CVE text", … for sentences. */
export function methodText(methods) {
  const words = methods.map((k) => METHOD[k])
  return words.length > 1 ? `${words.slice(0, -1).join(', ')} and ${words.at(-1)}` : (words[0] ?? '')
}

/** Only an exact CPE match needs no confirming. */
export const isExact = (methods) => methods.length === 1 && methods[0] === 'cpe'
