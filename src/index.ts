/**
 * Compliance Reviewer
 * Automated regulatory compliance checking for documents
 */

import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Types
export interface ComplianceReport {
  id: string;
  documentId: string;
  framework: string;
  generatedAt: Date;
  overallStatus: 'compliant' | 'non_compliant' | 'needs_review';
  score: number;
  findings: Finding[];
  summary: ComplianceSummary;
}

export interface Finding {
  requirementId: string;
  requirement: string;
  status: 'pass' | 'fail' | 'needs_review' | 'not_applicable';
  evidence: string;
  recommendation?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface ComplianceSummary {
  total: number;
  passed: number;
  failed: number;
  needsReview: number;
  notApplicable: number;
}

export interface Requirement {
  id: string;
  category: string;
  requirement: string;
  keywords: string[];
  mandatory: boolean;
}

export interface ReviewerConfig {
  dataDirectory: string;
}

// Compliance Frameworks
const GDPR_REQUIREMENTS: Requirement[] = [
  { id: 'GDPR-1', category: 'Data Protection', requirement: 'Data protection policy exists', keywords: ['data protection', 'privacy policy', 'data handling'], mandatory: true },
  { id: 'GDPR-2', category: 'Consent', requirement: 'Consent mechanism for data collection', keywords: ['consent', 'opt-in', 'agree'], mandatory: true },
  { id: 'GDPR-3', category: 'Rights', requirement: 'Data subject rights handled', keywords: ['right to access', 'right to erasure', 'data subject'], mandatory: true },
  { id: 'GDPR-4', category: 'Breach', requirement: 'Data breach notification process', keywords: ['breach notification', '72 hours', 'incident response'], mandatory: true },
  { id: 'GDPR-5', category: 'DPIA', requirement: 'Data protection impact assessment', keywords: ['data protection impact assessment', 'dpia', 'risk assessment'], mandatory: true },
  { id: 'GDPR-6', category: 'Privacy', requirement: 'Privacy by design implemented', keywords: ['privacy by design', 'data minimization', 'purpose limitation'], mandatory: true },
  { id: 'GDPR-7', category: 'DPO', requirement: 'Data protection officer designated', keywords: ['data protection officer', 'dpo', 'privacy officer'], mandatory: false },
  { id: 'GDPR-8', category: 'Transfer', requirement: 'Data transfer mechanisms in place', keywords: ['data transfer', 'sccs', 'standard contractual clauses'], mandatory: true },
];

const SOC2_REQUIREMENTS: Requirement[] = [
  { id: 'SOC2-1', category: 'Security', requirement: 'Security policies documented', keywords: ['security policy', 'information security', 'security program'], mandatory: true },
  { id: 'SOC2-2', category: 'Access', requirement: 'Access controls implemented', keywords: ['access control', 'authentication', 'authorization', 'mfa'], mandatory: true },
  { id: 'SOC2-3', category: 'Change', requirement: 'Change management process', keywords: ['change management', 'change control', 'change approval'], mandatory: true },
  { id: 'SOC2-4', category: 'Incident', requirement: 'Incident response plan', keywords: ['incident response', 'security incident', 'breach response'], mandatory: true },
  { id: 'SOC2-5', category: 'Vendor', requirement: 'Vendor management process', keywords: ['vendor management', 'third party', 'vendor assessment'], mandatory: true },
  { id: 'SOC2-6', category: 'Monitoring', requirement: 'Security monitoring in place', keywords: ['monitoring', 'logging', 'alerting', 'siem'], mandatory: true },
  { id: 'SOC2-7', category: 'Encryption', requirement: 'Data encryption implemented', keywords: ['encryption', 'tls', 'encrypt', 'cryptography'], mandatory: true },
  { id: 'SOC2-8', category: 'Backup', requirement: 'Backup and recovery process', keywords: ['backup', 'recovery', 'disaster recovery', 'bcp'], mandatory: true },
];

const HIPAA_REQUIREMENTS: Requirement[] = [
  { id: 'HIPAA-1', category: 'Privacy', requirement: 'HIPAA compliance policy', keywords: ['hipaa', 'health insurance', 'portability'], mandatory: true },
  { id: 'HIPAA-2', category: 'PHI', requirement: 'PHI protection measures', keywords: ['phi', 'protected health information', 'patient data'], mandatory: true },
  { id: 'HIPAA-3', category: 'BAA', requirement: 'Business associate agreements', keywords: ['business associate', 'baa', 'third party agreement'], mandatory: true },
  { id: 'HIPAA-4', category: 'Risk', requirement: 'Risk assessment process', keywords: ['risk assessment', 'risk analysis', 'security risk'], mandatory: true },
  { id: 'HIPAA-5', category: 'Breach', requirement: 'Breach notification procedures', keywords: ['breach notification', 'harm standard', 'hipaa breach'], mandatory: true },
  { id: 'HIPAA-6', category: 'Training', requirement: 'Security awareness training', keywords: ['training', 'awareness', 'security training'], mandatory: true },
  { id: 'HIPAA-7', category: 'Technical', requirement: 'Technical safeguards for PHI', keywords: ['technical safeguards', 'encryption', 'access control'], mandatory: true },
];

const SOX_REQUIREMENTS: Requirement[] = [
  { id: 'SOX-1', category: 'Controls', requirement: 'Internal controls documentation', keywords: ['internal controls', 'sox compliance', 'control documentation'], mandatory: true },
  { id: 'SOX-2', category: 'Financial', requirement: 'Financial reporting controls', keywords: ['financial controls', 'reporting controls', 'gaap'], mandatory: true },
  { id: 'SOX-3', category: 'IT', requirement: 'IT general controls', keywords: ['it general controls', 'itgc', 'system controls'], mandatory: true },
  { id: 'SOX-4', category: 'Audit', requirement: 'Audit trail implementation', keywords: ['audit trail', 'audit log', 'logging'], mandatory: true },
  { id: 'SOX-5', category: 'Access', requirement: 'User access controls', keywords: ['user access', 'access management', 'segregation'], mandatory: true },
  { id: 'SOX-6', category: 'Change', requirement: 'Change management controls', keywords: ['change management', 'sod', 'segregation of duties'], mandatory: true },
];

const FRAMEWORKS: Record<string, Requirement[]> = {
  GDPR: GDPR_REQUIREMENTS,
  SOC2: SOC2_REQUIREMENTS,
  HIPAA: HIPAA_REQUIREMENTS,
  SOX: SOX_REQUIREMENTS,
};

export class ComplianceReviewer {
  private config: ReviewerConfig;
  private reports: Map<string, ComplianceReport> = new Map();

  constructor(config?: Partial<ReviewerConfig>) {
    this.config = {
      dataDirectory: config?.dataDirectory || './data',
    };
  }

  async initialize(): Promise<void> {
    if (!fs.existsSync(this.config.dataDirectory)) {
      fs.mkdirSync(this.config.dataDirectory, { recursive: true });
    }
  }

  async review(documentPath: string, framework: string): Promise<ComplianceReport> {
    const text = await this.extractText(documentPath);
    const requirements = FRAMEWORKS[framework.toUpperCase()];
    
    if (!requirements) {
      throw new Error(`Unknown framework: ${framework}. Supported: ${Object.keys(FRAMEWORKS).join(', ')}`);
    }
    
    const findings: Finding[] = [];
    
    for (const req of requirements) {
      const finding = this.checkRequirement(text, req);
      findings.push(finding);
    }
    
    const summary = this.calculateSummary(findings);
    const score = this.calculateScore(summary);
    const overallStatus = this.determineStatus(summary, score);
    
    const report: ComplianceReport = {
      id: uuidv4(),
      documentId: path.basename(documentPath),
      framework,
      generatedAt: new Date(),
      overallStatus,
      score,
      findings,
      summary,
    };
    
    this.reports.set(report.id, report);
    await this.saveReport(report);
    
    return report;
  }

  private async extractText(documentPath: string): Promise<string> {
    // Simplified - would use actual PDF parsing
    try {
      return fs.readFileSync(documentPath, 'utf-8');
    } catch {
      return '';
    }
  }

  private checkRequirement(text: string, req: Requirement): Finding {
    const lowerText = text.toLowerCase();
    
    // Check for keywords
    const matchedKeywords = req.keywords.filter(kw => lowerText.includes(kw.toLowerCase()));
    
    let status: Finding['status'];
    let severity: Finding['severity'];
    let evidence: string;
    
    if (matchedKeywords.length > 0) {
      status = 'pass';
      severity = 'low';
      evidence = `Found relevant keywords: ${matchedKeywords.join(', ')}`;
    } else if (req.mandatory) {
      status = 'fail';
      severity = req.category === 'Security' || req.category === 'Data Protection' ? 'critical' : 'high';
      evidence = `No evidence of "${req.requirement}" found in document`;
    } else {
      status = 'needs_review';
      severity = 'low';
      evidence = 'Unable to determine compliance - manual review required';
    }
    
    let recommendation: string | undefined;
    if (status === 'fail') {
      recommendation = `Implement ${req.requirement.toLowerCase()} to achieve ${req.id} compliance`;
    } else if (status === 'needs_review') {
      recommendation = 'Manual review required to verify compliance';
    }
    
    return {
      requirementId: req.id,
      requirement: req.requirement,
      status,
      evidence,
      recommendation,
      severity,
    };
  }

  private calculateSummary(findings: Finding[]): ComplianceSummary {
    return {
      total: findings.length,
      passed: findings.filter(f => f.status === 'pass').length,
      failed: findings.filter(f => f.status === 'fail').length,
      needsReview: findings.filter(f => f.status === 'needs_review').length,
      notApplicable: findings.filter(f => f.status === 'not_applicable').length,
    };
  }

  private calculateScore(summary: ComplianceSummary): number {
    const applicable = summary.total - summary.notApplicable;
    if (applicable === 0) return 100;
    return Math.round((summary.passed / applicable) * 100);
  }

  private determineStatus(summary: ComplianceSummary, score: number): ComplianceReport['overallStatus'] {
    if (summary.failed > 0) return 'non_compliant';
    if (summary.needsReview > 0 || score < 80) return 'needs_review';
    return 'compliant';
  }

  async getReport(reportId: string): Promise<ComplianceReport | undefined> {
    return this.reports.get(reportId);
  }

  async generateReport(reportId: string): Promise<string> {
    const report = this.reports.get(reportId);
    if (!report) throw new Error('Report not found');
    
    return this.formatReport(report);
  }

  private formatReport(report: ComplianceReport): string {
    let output = '';
    
    output += '='.repeat(60) + '\n';
    output += `COMPLIANCE REVIEW REPORT\n`;
    output += '='.repeat(60) + '\n\n';
    
    output += `Framework: ${report.framework}\n`;
    output += `Document: ${report.documentId}\n`;
    output += `Generated: ${report.generatedAt.toISOString()}\n`;
    output += `Status: ${report.overallStatus.toUpperCase()}\n`;
    output += `Score: ${report.score}%\n\n`;
    
    output += '-'.repeat(60) + '\n';
    output += 'SUMMARY\n';
    output += '-'.repeat(60) + '\n';
    output += `Total Requirements: ${report.summary.total}\n`;
    output += `Passed: ${report.summary.passed}\n`;
    output += `Failed: ${report.summary.failed}\n`;
    output += `Needs Review: ${report.summary.needsReview}\n`;
    output += `Not Applicable: ${report.summary.notApplicable}\n\n`;
    
    output += '-'.repeat(60) + '\n';
    output += 'FINDINGS\n';
    output += '-'.repeat(60) + '\n\n';
    
    // Group by status
    const critical = report.findings.filter(f => f.severity === 'critical');
    const high = report.findings.filter(f => f.severity === 'high');
    const other = report.findings.filter(f => f.severity !== 'critical' && f.severity !== 'high');
    
    if (critical.length > 0) {
      output += 'CRITICAL FINDINGS:\n';
      for (const f of critical) {
        output += `  [${f.status.toUpperCase()}] ${f.requirementId}: ${f.requirement}\n`;
        output += `    Evidence: ${f.evidence}\n`;
        if (f.recommendation) output += `    Recommendation: ${f.recommendation}\n`;
      }
      output += '\n';
    }
    
    if (high.length > 0) {
      output += 'HIGH PRIORITY FINDINGS:\n';
      for (const f of high) {
        output += `  [${f.status.toUpperCase()}] ${f.requirementId}: ${f.requirement}\n`;
        output += `    Evidence: ${f.evidence}\n`;
        if (f.recommendation) output += `    Recommendation: ${f.recommendation}\n`;
      }
      output += '\n';
    }
    
    if (other.length > 0) {
      output += 'OTHER FINDINGS:\n';
      for (const f of other) {
        output += `  [${f.status.toUpperCase()}] ${f.requirementId}: ${f.requirement}\n`;
      }
      output += '\n';
    }
    
    return output;
  }

  private async saveReport(report: ComplianceReport): Promise<void> {
    const filePath = path.join(this.config.dataDirectory, `${report.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
  }

  addCustomFramework(name: string, requirements: Requirement[]): void {
    FRAMEWORKS[name.toUpperCase()] = requirements;
  }

  listFrameworks(): string[] {
    return Object.keys(FRAMEWORKS);
  }
}

export function createReviewer(config?: Partial<ReviewerConfig>): ComplianceReviewer {
  return new ComplianceReviewer(config);
}
