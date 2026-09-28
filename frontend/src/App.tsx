import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './app/AppLayout'
import { AuditTrailPage } from './features/audit/AuditTrailPage'
import { AuthProvider } from './features/auth/AuthContext'
import { LoginPage } from './features/auth/LoginPage'
import { RequireAuth } from './features/auth/RequireAuth'
import { RequireCapability } from './features/auth/RequireCapability'
import { ControlsPage } from './features/controls/ControlsPage'
import { DashboardPage } from './features/dashboard/DashboardPage'
import { ExecutiveSummaryPage } from './features/reports/ExecutiveSummaryPage'
import { ExceptionDetailPage } from './features/exceptions/ExceptionDetailPage'
import { ExceptionsPage } from './features/exceptions/ExceptionsPage'
import { FindingDetailPage } from './features/findings/FindingDetailPage'
import { FindingsBacklogPage } from './features/findings/FindingsBacklogPage'
import { ApplicationDetailPage } from './features/inventory/ApplicationDetailPage'
import { InventoryListPage } from './features/inventory/InventoryListPage'
import { PentestBoardPage } from './features/pentest/PentestBoardPage'
import { PentestReportPage } from './features/pentest/PentestReportPage'
import { PolicyPage } from './features/policy/PolicyPage'
import { SbomIngestionPage } from './features/sbom/SbomIngestionPage'
import { IntegrationsPage } from './features/settings/IntegrationsPage'
import { UserDetailPage } from './features/settings/UserDetailPage'
import { UsersListPage } from './features/settings/UsersListPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Vulnerability data is refreshed by background sync (FR-3.1), not per keystroke;
      // a short stale window keeps the dashboard current without hammering the API.
      staleTime: 30_000,
      retry: 1,
    },
  },
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/*"
              element={
                <RequireAuth>
                  <AppLayout>
                    <Routes>
                      <Route
                        index
                        element={
                          <RequireCapability capability="viewDashboard">
                            <DashboardPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="findings"
                        element={
                          <RequireCapability capability="viewFindings">
                            <FindingsBacklogPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="findings/:findingId"
                        element={
                          <RequireCapability capability="viewFindings">
                            <FindingDetailPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="exceptions"
                        element={
                          <RequireCapability capability="viewExceptions">
                            <ExceptionsPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="exceptions/:exceptionId"
                        element={
                          <RequireCapability capability="viewExceptions">
                            <ExceptionDetailPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="controls"
                        element={
                          <RequireCapability capability="viewControls">
                            <ControlsPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="reports"
                        element={
                          <RequireCapability capability="viewReports">
                            <ExecutiveSummaryPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="applications"
                        element={
                          <RequireCapability capability="viewInventory">
                            <InventoryListPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="applications/:appId"
                        element={
                          <RequireCapability capability="viewInventory">
                            <ApplicationDetailPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="pentest/board"
                        element={
                          <RequireCapability capability="viewPentestProjects">
                            <PentestBoardPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="pentest/report"
                        element={
                          <RequireCapability capability="viewPentestCostReport">
                            <PentestReportPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="sbom"
                        element={
                          <RequireCapability capability="manageSbomIngestion">
                            <SbomIngestionPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="policy"
                        element={
                          <RequireCapability capability="viewPolicy">
                            <PolicyPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="audit"
                        element={
                          <RequireCapability capability="viewAuditTrail">
                            <AuditTrailPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="settings/users"
                        element={
                          <RequireCapability capability="manageUsers">
                            <UsersListPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="settings/users/:userId"
                        element={
                          <RequireCapability capability="manageUsers">
                            <UserDetailPage />
                          </RequireCapability>
                        }
                      />
                      <Route
                        path="settings/integrations"
                        element={
                          <RequireCapability capability="manageIntegrations">
                            <IntegrationsPage />
                          </RequireCapability>
                        }
                      />
                      <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                  </AppLayout>
                </RequireAuth>
              }
            />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
