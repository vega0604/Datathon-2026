import { useState } from 'react'
import { InsightsSummary } from './views/InsightsSummary'
import { FixFirstQueue } from './views/FixFirstQueue'

export default function App() {
  const [page, setPage] = useState('insights')

  return page === 'insights' ? (
    <InsightsSummary onOpenFixFirst={() => setPage('fixFirst')} />
  ) : (
    <FixFirstQueue onOpenInsights={() => setPage('insights')} />
  )
}
