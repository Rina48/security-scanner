import { ErrorBoundary } from "./components/ErrorBoundary";
import { ScannerPage } from "./pages/ScannerPage";

function App() {
  return (
    <ErrorBoundary>
      <ScannerPage />
    </ErrorBoundary>
  );
}

export default App;
