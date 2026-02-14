# Compliance Reviewer

Automated regulatory compliance checking tool for documents.

## Features

- Support for GDPR, SOC2, HIPAA, SOX frameworks
- Keyword-based compliance checking
- Compliance score calculation
- Detailed findings with recommendations
- Custom framework support

## Installation

```bash
npm install
npm run build
```

## Usage

```typescript
import { ComplianceReviewer } from './src';

const reviewer = new ComplianceReviewer();
await reviewer.initialize();

// Review a document
const report = await reviewer.review('./policy.pdf', 'GDPR');
console.log(`Compliance Score: ${report.score}%`);
console.log(`Status: ${report.overallStatus}`);

// Generate detailed report
const detailed = await reviewer.generateReport(report.id);
console.log(detailed);
```

## Supported Frameworks

- **GDPR** - General Data Protection Regulation
- **SOC2** - Service Organization Control 2
- **HIPAA** - Health Insurance Portability and Accountability Act
- **SOX** - Sarbanes-Oxley Act

## License

MIT
