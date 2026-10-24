import React, { useState, useRef } from 'react';
import {
  scanTextPayload,
  scanFilePayload,
  verifyAuditChain,
  ScanResponse,
  Finding,
  DestinationType,
  RecipientType,
  DataClassification,
  PolicyAction,
  AuditVerificationResult,
} from '../api/client';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Copy,
  Check,
  Zap,
  AlertTriangle,
  FileCheck2,
  CheckCircle2,
  Layers,
  Fingerprint,
  Bot,
  UserCheck,
  Clock,
  Eye,
  RefreshCw,
  Upload,
  FileText,
  Trash2,
  Building,
  FileCode,
  FileSpreadsheet,
} from 'lucide-react';

const SYNTHETIC_SAMPLE_LEAK = `Incident Report #4092:
Developer submitted customer issue notes:
- Customer Name: Jane Doe
- Contact: jane.doe.sec@example.com, Phone: +1 (555) 349-1102
- SSN on file: 123-45-6789
- Billing Account: 4111-1111-1111-1111 (Visa card via checkout)
- CI/CD Deployment log excerpt:
  export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
  export OPENAI_API_KEY="sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
  export GITHUB_TOKEN="ghp_111122223333444455556666777788889999"
  db_password = 'ProductionMasterSecretKey2026!'
`;

const SYNTHETIC_SAMPLE_CLEAN = `Sprint Retrospective & Architectural Notes:
Engineering velocity was 42 story points for the sprint.
Team refactored the in-memory redis cache and improved index compaction latency.
All integration smoke tests passed. Deployed build 2.14.0 to internal staging cluster.`;

const SYNTHETIC_SAMPLE_PII = `Patient Intake Form:
Full Name: Michael R. Henderson
Primary Email: m.henderson@example.org
Phone: (206) 555-0194
Government ID (SSN): 987-65-4320
Insurance Account Number: INS-99482-TX`;

const SUPPORTED_EXTENSIONS = [
  '.txt', '.log', '.csv', '.json', '.yaml', '.yml', '.xml',
  '.md', '.html', '.css', '.js', '.ts', '.py', '.java',
  '.sql', '.env', '.ini', '.conf', '.properties',
  '.pdf', '.docx'
];

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

type InputTab = 'text' | 'file' | 'sample';

export type FileScanPhase =
  | 'idle'
  | 'selecting'
  | 'ready'
  | 'uploading'
  | 'scanning'
  | 'success'
  | 'unsupported_format'
  | 'file_too_large'
  | 'extraction_failure'
  | 'server_error';

export const ScanWorkbench: React.FC = () => {
  // Input mode & payload state
  const [activeTab, setActiveTab] = useState<InputTab>('text');
  const [inputText, setInputText] = useState<string>(SYNTHETIC_SAMPLE_LEAK);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePreviewText, setFilePreviewText] = useState<string>('');
  const [fileError, setFileError] = useState<string | null>(null);
  const [fileScanPhase, setFileScanPhase] = useState<FileScanPhase>('idle');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Sharing Context settings
  const [redactionMode, setRedactionMode] = useState<'placeholder' | 'synthetic'>('placeholder');
  const [destination, setDestination] = useState<DestinationType>('PUBLIC_LLM');
  const [recipient, setRecipient] = useState<RecipientType>('PUBLIC');
  const [classification, setClassification] = useState<DataClassification>('CONFIDENTIAL');
  const [orgId, setOrgId] = useState<string>('default');

  // Execution state
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  // Audit chain verification state
  const [verifyingAudit, setVerifyingAudit] = useState<boolean>(false);
  const [auditResult, setAuditResult] = useState<AuditVerificationResult | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  // File selection & validation
  const validateAndSelectFile = (file: File) => {
    setFileError(null);
    setFilePreviewText('');

    if (file.size > MAX_FILE_SIZE_BYTES) {
      setFileScanPhase('file_too_large');
      setFileError(`File size exceeds 5 MB limit (${(file.size / (1024 * 1024)).toFixed(2)} MB). Please select a smaller file.`);
      setSelectedFile(null);
      return;
    }

    const ext = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!SUPPORTED_EXTENSIONS.includes(ext)) {
      setFileScanPhase('unsupported_format');
      setFileError(`Unsupported file format "${ext}". Supported types: ${SUPPORTED_EXTENSIONS.join(', ')}`);
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setFileScanPhase('ready');

    // Client-side preview for text files
    if (['.txt', '.log', '.csv', '.json', '.yaml', '.yml', '.xml', '.md', '.html', '.css', '.js', '.ts', '.py', '.java', '.sql', '.env', '.ini', '.conf', '.properties'].includes(ext)) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target?.result as string;
        setFilePreviewText(text ? text.slice(0, 4000) : '');
      };
      reader.onerror = () => {
        setFilePreviewText('(Unable to read preview directly in browser. Server will extract text during scan.)');
      };
      reader.readAsText(file.slice(0, 50000));
    } else {
      setFilePreviewText(`[Binary Document: ${file.name}] Server-side deterministic text extractor will safely parse plain text from this ${ext.toUpperCase()} payload.`);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSelectFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSelectFile(e.target.files[0]);
    }
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setFilePreviewText('');
    setFileError(null);
    setFileScanPhase('idle');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Scan dispatcher
  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);

    const sharingContext = {
      destination,
      recipient,
      classification,
      actor_id: 'analyst_workbench',
      org_id: orgId,
    };

    const options = {
      enable_entropy: true,
      redaction_mode: redactionMode,
    };

    try {
      if (activeTab === 'file') {
        if (!selectedFile) {
          setError('Please select or upload a valid file to analyze.');
          setFileScanPhase('idle');
          setLoading(false);
          return;
        }

        setFileScanPhase('uploading');
        // Visually transition to scanning
        const timer = setTimeout(() => {
          setFileScanPhase((curr) => (curr === 'uploading' ? 'scanning' : curr));
        }, 180);

        const data = await scanFilePayload(selectedFile, options, sharingContext);
        clearTimeout(timer);
        setResult(data);
        setFileScanPhase('success');
      } else {
        if (!inputText.trim()) {
          setError('Please enter or paste text to analyze.');
          setLoading(false);
          return;
        }
        const data = await scanTextPayload(inputText, options, sharingContext);
        setResult(data);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Analysis failed';
      setError(msg);
      if (activeTab === 'file') {
        const lowerMsg = msg.toLowerCase();
        if (msg.includes('413') || lowerMsg.includes('exceeds')) {
          setFileScanPhase('file_too_large');
          setFileError(msg);
        } else if (msg.includes('415') || lowerMsg.includes('unsupported file format')) {
          setFileScanPhase('unsupported_format');
          setFileError(msg);
        } else if (msg.includes('500') || lowerMsg.includes('server error') || lowerMsg.includes('failed to fetch')) {
          setFileScanPhase('server_error');
          setFileError(msg);
        } else {
          setFileScanPhase('extraction_failure');
          setFileError(msg);
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    setVerifyingAudit(true);
    setAuditError(null);
    try {
      const res = await verifyAuditChain();
      setAuditResult(res);
    } catch (err) {
      setAuditError(err instanceof Error ? err.message : 'Audit chain verification failed');
    } finally {
      setVerifyingAudit(false);
    }
  };

  const handleCopyRedacted = () => {
    if (result?.redacted_text) {
      navigator.clipboard.writeText(result.redacted_text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const renderDecisionBadge = (decision?: PolicyAction | string) => {
    switch (decision) {
      case 'BLOCK':
        return (
          <span className="badge badge-block" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <ShieldAlert size={14} strokeWidth={2.5} />
            BLOCK
          </span>
        );
      case 'REQUIRE_APPROVAL':
        return (
          <span className="badge badge-approval" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <Clock size={14} strokeWidth={2} />
            REQUIRE APPROVAL
          </span>
        );
      case 'WARN':
        return (
          <span className="badge badge-warn" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <AlertTriangle size={14} strokeWidth={2} />
            WARN
          </span>
        );
      case 'REDACT':
        return (
          <span className="badge badge-approval" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <Lock size={14} strokeWidth={2} />
            REDACT
          </span>
        );
      default:
        return (
          <span className="badge badge-allow" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <CheckCircle2 size={14} strokeWidth={2} />
            ALLOW
          </span>
        );
    }
  };

  const renderSeverityBadge = (sev: string) => {
    let className = 'badge-allow';
    if (sev === 'CRITICAL') className = 'badge-block';
    else if (sev === 'HIGH') className = 'badge-approval';
    else if (sev === 'MEDIUM') className = 'badge-warn';

    return <span className={`badge ${className}`} style={{ fontSize: '0.66rem' }}>{sev}</span>;
  };

  const getFileIcon = (filename: string) => {
    const ext = filename.split('.').pop()?.toLowerCase();
    if (['csv', 'json', 'yaml', 'yml'].includes(ext || '')) {
      return <FileSpreadsheet size={18} color="var(--text-secondary)" />;
    }
    if (['py', 'ts', 'js', 'java', 'sql', 'html', 'css', 'env'].includes(ext || '')) {
      return <FileCode size={18} color="var(--text-secondary)" />;
    }
    return <FileText size={18} color="var(--text-secondary)" />;
  };

  const isScanDisabled = loading || (activeTab === 'file' ? !selectedFile : !inputText.trim());

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '1440px', margin: '0 auto', width: '100%' }}>
      {/* Workbench Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <h1 style={{ fontSize: '1.45rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              Scan Workbench
            </h1>
            <span className="badge badge-mono" style={{ fontSize: '0.68rem' }}>
              Multi-Input DLP Egress
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '720px', lineHeight: 1.45 }}>
            Evaluate sensitive code snippets, files, and documents against deterministic DLP policies, inspect redacted outputs, and enforce company-specific security boundaries.
          </p>
        </div>

        {/* Input Mode Navigation Tabs */}
        <div style={{ display: 'flex', alignItems: 'center', background: 'var(--bg-surface)', border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-sm)', padding: '3px' }}>
          <button
            className={`btn-ghost ${activeTab === 'text' ? 'text-primary' : ''}`}
            onClick={() => setActiveTab('text')}
            style={{
              fontSize: '0.78rem',
              padding: '6px 14px',
              borderRadius: 'var(--radius-xs)',
              background: activeTab === 'text' ? 'var(--bg-card)' : 'transparent',
              color: activeTab === 'text' ? '#ffffff' : 'var(--text-secondary)',
              border: activeTab === 'text' ? '1px solid var(--border-strong)' : '1px solid transparent',
            }}
          >
            Paste Text
          </button>
          <button
            className={`btn-ghost ${activeTab === 'file' ? 'text-primary' : ''}`}
            onClick={() => setActiveTab('file')}
            style={{
              fontSize: '0.78rem',
              padding: '6px 14px',
              borderRadius: 'var(--radius-xs)',
              background: activeTab === 'file' ? 'var(--bg-card)' : 'transparent',
              color: activeTab === 'file' ? '#ffffff' : 'var(--text-secondary)',
              border: activeTab === 'file' ? '1px solid var(--border-strong)' : '1px solid transparent',
            }}
          >
            Upload File
          </button>
          <button
            className={`btn-ghost ${activeTab === 'sample' ? 'text-primary' : ''}`}
            onClick={() => setActiveTab('sample')}
            style={{
              fontSize: '0.78rem',
              padding: '6px 14px',
              borderRadius: 'var(--radius-xs)',
              background: activeTab === 'sample' ? 'var(--bg-card)' : 'transparent',
              color: activeTab === 'sample' ? '#ffffff' : 'var(--text-secondary)',
              border: activeTab === 'sample' ? '1px solid var(--border-strong)' : '1px solid transparent',
            }}
          >
            Scan Sample
          </button>
        </div>
      </div>

      {/* Input Card Container */}
      <div className="card" style={{ padding: '20px' }}>
        {/* Tab 1: Paste Text */}
        {activeTab === 'text' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Payload Content (Direct Text)
              </label>
              <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                {inputText.length.toLocaleString()} / 1,000,000 chars
              </span>
            </div>
            <textarea
              id="payload-input"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste code snippet, prompt payload, configuration file, or document text for sensitive data inspection..."
              rows={8}
              className="font-mono"
              style={{
                width: '100%',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-primary)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                padding: '12px 14px',
                fontSize: '0.82rem',
                lineHeight: 1.5,
                resize: 'vertical',
                marginBottom: '16px',
              }}
            />
          </div>
        )}

        {/* Tab 2: Upload File */}
        {activeTab === 'file' && (
          <div style={{ marginBottom: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Document or Code Upload
                </label>
                {fileScanPhase === 'uploading' && (
                  <span className="badge badge-outline" style={{ fontSize: '0.68rem', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <RefreshCw size={10} className="animate-spin" /> Uploading Payload...
                  </span>
                )}
                {fileScanPhase === 'scanning' && (
                  <span className="badge badge-outline" style={{ fontSize: '0.68rem', display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <RefreshCw size={10} className="animate-spin" /> Extracting Text & DLP Scanning...
                  </span>
                )}
                {fileScanPhase === 'ready' && (
                  <span className="badge badge-allow" style={{ fontSize: '0.66rem' }}>
                    Ready for Scan
                  </span>
                )}
                {fileScanPhase === 'success' && (
                  <span className="badge badge-allow" style={{ fontSize: '0.66rem' }}>
                    ✓ Scan Complete
                  </span>
                )}
              </div>
              <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                Max 5 MB • Safe Text Extraction
              </span>
            </div>

            {/* Hidden native input */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileInputChange}
              style={{ display: 'none' }}
              accept={SUPPORTED_EXTENSIONS.join(',')}
            />

            {/* Uploading or Scanning In-Progress Indicator Banner */}
            {(fileScanPhase === 'uploading' || fileScanPhase === 'scanning') && (
              <div
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-strong)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '14px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '14px',
                  marginBottom: '12px',
                }}
              >
                <RefreshCw size={18} className="animate-spin" color="#ffffff" />
                <div>
                  <div style={{ fontSize: '0.84rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {fileScanPhase === 'uploading'
                      ? 'Streaming File Payload to Secure Memory...'
                      : 'Extracting Plain Text & Evaluating DLP Policies...'}
                  </div>
                  <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
                    {fileScanPhase === 'uploading'
                      ? 'File bytes are safely read into bounded memory with zero temporary disk retention.'
                      : 'Running regex detectors, Shannon entropy, Luhn validator, and advisory AI analysis.'}
                  </div>
                </div>
              </div>
            )}

            {!selectedFile ? (
              /* Dropzone */
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                style={{
                  border: isDragging ? '2px dashed #ffffff' : '1px dashed var(--border-strong)',
                  borderRadius: 'var(--radius-sm)',
                  background: isDragging ? 'var(--bg-hover)' : 'var(--bg-surface)',
                  padding: '36px 20px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  marginBottom: '12px',
                }}
              >
                <Upload size={28} color="var(--text-secondary)" style={{ margin: '0 auto 10px', opacity: 0.8 }} />
                <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                  Drag & drop file here, or <span style={{ textDecoration: 'underline' }}>Browse files</span>
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', maxWidth: '580px', margin: '0 auto', lineHeight: 1.4 }}>
                  Supported formats: Code (.py, .ts, .js, .java, .sql), Structured (.csv, .json, .yaml, .xml), Config (.env, .ini, .conf), and Documents (.pdf, .docx, .txt, .md).
                </div>
              </div>
            ) : (
              /* File Selected Info & Preview */
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '12px' }}>
                <div
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '10px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    {getFileIcon(selectedFile.name)}
                    <div>
                      <div style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {selectedFile.name}
                      </div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.type || 'plain document'}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <button
                      className="btn-ghost"
                      onClick={() => fileInputRef.current?.click()}
                      style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                    >
                      Replace
                    </button>
                    <button
                      className="btn-ghost"
                      onClick={handleRemoveFile}
                      style={{ fontSize: '0.75rem', padding: '4px 8px', color: '#a3a3a3' }}
                    >
                      <Trash2 size={13} />
                      Remove
                    </button>
                  </div>
                </div>

                {/* Pre-scan text preview */}
                {filePreviewText && (
                  <div>
                    <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
                      Extracted Text Preview (Safe Content View)
                    </div>
                    <div
                      className="font-mono card-inset"
                      style={{
                        padding: '10px 14px',
                        fontSize: '0.76rem',
                        lineHeight: 1.45,
                        color: 'var(--text-secondary)',
                        maxHeight: '140px',
                        overflowY: 'auto',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {filePreviewText}
                    </div>
                  </div>
                )}

                {/* PDF/DOCX Disclaimer */}
                {selectedFile.name.toLowerCase().endsWith('.pdf') || selectedFile.name.toLowerCase().endsWith('.docx') ? (
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    Note: For PDF and DOCX documents, plain text is extracted safely. Embedded graphics, scanned images, and comments require separate OCR/inspection.
                  </div>
                ) : null}
              </div>
            )}

            {fileError && (
              <div
                style={{
                  padding: '12px 16px',
                  background: 'var(--bg-surface)',
                  border: '1px solid #737373',
                  borderRadius: 'var(--radius-sm)',
                  color: '#f5f5f5',
                  fontSize: '0.82rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  marginBottom: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <AlertTriangle size={15} color="#ffffff" />
                  <span style={{ fontWeight: 600 }}>
                    {fileScanPhase === 'unsupported_format' && 'Unsupported Format Error (415)'}
                    {fileScanPhase === 'file_too_large' && 'File Size Limit Exceeded (413)'}
                    {fileScanPhase === 'extraction_failure' && 'Text Extraction Failure (400)'}
                    {fileScanPhase === 'server_error' && 'Server Scan Error (500)'}
                    {(!['unsupported_format', 'file_too_large', 'extraction_failure', 'server_error'].includes(fileScanPhase)) && 'File Validation Error'}
                  </span>
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', paddingLeft: '23px', lineHeight: 1.4 }}>
                  {fileError}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Scan Sample */}
        {activeTab === 'sample' && (
          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '8px' }}>
              Synthetic Security Test Payloads
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '14px' }}>
              <div
                className="card-inset"
                style={{
                  padding: '12px 14px',
                  cursor: 'pointer',
                  border: inputText === SYNTHETIC_SAMPLE_LEAK ? '1px solid #ffffff' : '1px solid var(--border-primary)',
                }}
                onClick={() => {
                  setInputText(SYNTHETIC_SAMPLE_LEAK);
                  setDestination('PUBLIC_LLM');
                  setRecipient('PUBLIC');
                  setClassification('CONFIDENTIAL');
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Credential & API Secret Leak
                  </span>
                  <span className="badge badge-block" style={{ fontSize: '0.62rem' }}>BLOCK</span>
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                  AWS Keys, OpenAI token, GitHub PAT, SSN, and Credit Card sent toward Public LLM perimeter.
                </div>
              </div>

              <div
                className="card-inset"
                style={{
                  padding: '12px 14px',
                  cursor: 'pointer',
                  border: inputText === SYNTHETIC_SAMPLE_PII ? '1px solid #ffffff' : '1px solid var(--border-primary)',
                }}
                onClick={() => {
                  setInputText(SYNTHETIC_SAMPLE_PII);
                  setDestination('EXTERNAL_SAAS');
                  setRecipient('THIRD_PARTY_CONTRACTOR');
                  setClassification('RESTRICTED');
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Customer PII & Medical Intake
                  </span>
                  <span className="badge badge-approval" style={{ fontSize: '0.62rem' }}>APPROVAL</span>
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                  Patient record with name, email, phone, and government identification sent to external SaaS.
                </div>
              </div>

              <div
                className="card-inset"
                style={{
                  padding: '12px 14px',
                  cursor: 'pointer',
                  border: inputText === SYNTHETIC_SAMPLE_CLEAN ? '1px solid #ffffff' : '1px solid var(--border-primary)',
                }}
                onClick={() => {
                  setInputText(SYNTHETIC_SAMPLE_CLEAN);
                  setDestination('INTERNAL_SERVICE');
                  setRecipient('INTERNAL_EMPLOYEE');
                  setClassification('INTERNAL');
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Clean Architectural Retrospective
                  </span>
                  <span className="badge badge-allow" style={{ fontSize: '0.62rem' }}>ALLOW</span>
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                  Standard engineering sprint retrospective notes without sensitive credentials or consumer PII.
                </div>
              </div>
            </div>

            {/* Inset Textarea for sample preview */}
            <textarea
              id="payload-input-sample"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              rows={5}
              className="font-mono"
              style={{
                width: '100%',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-primary)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                padding: '10px 12px',
                fontSize: '0.8rem',
                lineHeight: 1.45,
                resize: 'vertical',
              }}
            />
          </div>
        )}

        {/* Sharing Context & Governance Controls Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '12px',
            padding: '14px',
            background: 'var(--bg-surface)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            marginBottom: '16px',
          }}
        >
          {/* Organization Tenant Context */}
          <div>
            <label style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              <Building size={11} />
              <span>Company Tenant</span>
            </label>
            <select
              id="select-org-context"
              value={orgId}
              onChange={(e) => setOrgId(e.target.value)}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="default">Global / Default Rules</option>
              <option value="org_acme">Acme Corp (Demo Tenant)</option>
              <option value="org_cybershield">CyberShield (Demo Tenant)</option>
              <option value="org_fintech">FinTech Secure (Demo Tenant)</option>
            </select>
          </div>

          {/* Destination Perimeter */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Destination Perimeter
            </label>
            <select
              id="select-destination"
              value={destination}
              onChange={(e) => setDestination(e.target.value as DestinationType)}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="PUBLIC_LLM">PUBLIC_LLM (OpenAI, Public Models)</option>
              <option value="EXTERNAL_SAAS">EXTERNAL_SAAS (Third-party Cloud)</option>
              <option value="INTERNAL_SERVICE">INTERNAL_SERVICE (On-prem / VPC)</option>
              <option value="INTERNAL_VECTOR_DB">INTERNAL_VECTOR_DB (Internal RAG)</option>
              <option value="UNSPECIFIED">UNSPECIFIED (Ambiguous)</option>
            </select>
          </div>

          {/* Recipient Trust */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Recipient Trust Level
            </label>
            <select
              id="select-recipient"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value as RecipientType)}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="PUBLIC">PUBLIC (Untrusted / External)</option>
              <option value="THIRD_PARTY_CONTRACTOR">THIRD_PARTY_CONTRACTOR (External)</option>
              <option value="INTERNAL_EMPLOYEE">INTERNAL_EMPLOYEE (Verified Org)</option>
              <option value="AUTHORIZED_ANALYST">AUTHORIZED_ANALYST (Compliance Tier)</option>
              <option value="UNKNOWN">UNKNOWN (Ambiguous)</option>
            </select>
          </div>

          {/* Classification */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Data Classification
            </label>
            <select
              id="select-classification"
              value={classification}
              onChange={(e) => setClassification(e.target.value as DataClassification)}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="PUBLIC">PUBLIC (Low sensitivity)</option>
              <option value="INTERNAL">INTERNAL (Internal business use)</option>
              <option value="CONFIDENTIAL">CONFIDENTIAL (Proprietary / Regulated)</option>
              <option value="RESTRICTED">RESTRICTED (Critical Keys, PCI)</option>
            </select>
          </div>

          {/* Redaction Strategy */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Redaction Strategy
            </label>
            <select
              id="select-redaction-mode"
              value={redactionMode}
              onChange={(e) => setRedactionMode(e.target.value as 'placeholder' | 'synthetic')}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="placeholder">Placeholders ([REDACTED_AWS_KEY])</option>
              <option value="synthetic">Synthetic Tokens ([SECRET_TOKEN_01])</option>
            </select>
          </div>
        </div>

        {/* Scan Action Row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>Tenant context: <strong>{orgId}</strong></span>
            <span>•</span>
            <span>Shannon entropy, Luhn verification, regex detectors, and deterministic policy precedence active.</span>
          </div>

          <button
            id="btn-analyze-payload"
            className="btn-primary"
            onClick={handleAnalyze}
            disabled={isScanDisabled}
            style={{ padding: '9px 22px', minWidth: '160px' }}
          >
            {loading ? (
              <>
                <RefreshCw size={14} className="animate-spin" />
                <span>
                  {activeTab === 'file'
                    ? fileScanPhase === 'uploading'
                      ? 'Uploading Payload...'
                      : 'Scanning & Evaluating...'
                    : 'Evaluating...'}
                </span>
              </>
            ) : (
              <>
                <Zap size={14} strokeWidth={2} />
                <span>{activeTab === 'file' ? 'Scan Uploaded File' : 'Scan Payload'}</span>
              </>
            )}
          </button>
        </div>

        {error && (
          <div
            className="card"
            style={{
              marginTop: '14px',
              padding: '12px 16px',
              border: '1px solid #737373',
              color: '#f5f5f5',
              fontSize: '0.82rem',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <AlertTriangle size={15} color="#ffffff" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis Results View */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Executive Summary Bar */}
          <div
            className="card"
            style={{
              padding: '18px 22px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
              gap: '16px',
              alignItems: 'center',
              background: 'var(--bg-surface)',
            }}
          >
            {/* Deterministic Decision */}
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                Deterministic Policy Decision
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                {renderDecisionBadge(result.policy_decision)}
                {result.policy_decision === 'BLOCK' && (
                  <span className="badge badge-mono" style={{ fontSize: '0.66rem' }}>
                    Hard-Block Invariant
                  </span>
                )}
              </div>
            </div>

            {/* Heuristic Risk Score */}
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                Heuristic Risk Score
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
                <span style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {result.risk_score}
                </span>
                <span className="font-mono text-muted" style={{ fontSize: '0.8rem' }}>/ 100</span>
                <span className="badge badge-outline" style={{ fontSize: '0.68rem' }}>
                  {result.risk_band}
                </span>
              </div>
            </div>

            {/* Source Details */}
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                Source & Scope
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                <span className="badge badge-mono" style={{ fontSize: '0.68rem' }}>
                  {result.source_type === 'file' ? (result.filename || 'Uploaded File') : 'Pasted Text'}
                </span>
                {result.file_size_bytes ? (
                  <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                    {(result.file_size_bytes / 1024).toFixed(1)} KB
                  </span>
                ) : null}
                <span className="badge badge-outline" style={{ fontSize: '0.66rem' }}>
                  Org: {result.context?.org_id || orgId}
                </span>
              </div>
            </div>

            {/* Audit Chain Link */}
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                Cryptographic Audit Seal
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span
                  className="font-mono text-muted"
                  style={{
                    fontSize: '0.72rem',
                    background: '#151515',
                    padding: '3px 6px',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border-primary)',
                    maxWidth: '120px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                  title={result.audit_event_hash || ''}
                >
                  {result.audit_event_hash ? `${result.audit_event_hash.slice(0, 12)}...` : 'N/A'}
                </span>
                <button
                  id="btn-verify-audit"
                  className="btn-secondary"
                  onClick={handleVerifyChain}
                  disabled={verifyingAudit}
                  style={{ fontSize: '0.72rem', padding: '3px 8px' }}
                >
                  <Fingerprint size={11} />
                  {verifyingAudit ? 'Verifying...' : 'Verify Chain'}
                </button>
              </div>
            </div>
          </div>

          {/* File Extraction & Inspection Banner */}
          {result.source_type === 'file' && (
            <div
              className="card"
              style={{
                padding: '12px 18px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-primary)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                {getFileIcon(result.filename || 'document.txt')}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {result.filename || 'Uploaded File'}
                    </span>
                    <span className="badge badge-mono" style={{ fontSize: '0.65rem' }}>
                      In-Memory Safe Extraction
                    </span>
                    <span className="badge badge-outline" style={{ fontSize: '0.65rem' }}>
                      Zero Disk Retention
                    </span>
                    <span className="badge badge-allow" style={{ fontSize: '0.65rem' }}>
                      Extraction Verified
                    </span>
                  </div>
                  {result.extraction_note && (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      {result.extraction_note}
                    </div>
                  )}
                </div>
              </div>
              {result.file_size_bytes ? (
                <span className="font-mono text-muted" style={{ fontSize: '0.74rem' }}>
                  {(result.file_size_bytes / 1024).toFixed(1)} KB payload
                </span>
              ) : null}
            </div>
          )}

          {/* Optional Extraction Note Banner for non-file if present */}
          {result.source_type !== 'file' && result.extraction_note && (
            <div
              className="card"
              style={{
                padding: '10px 14px',
                fontSize: '0.78rem',
                color: 'var(--text-secondary)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: 'var(--bg-surface)',
              }}
            >
              <InfoBadge note={result.extraction_note} />
            </div>
          )}

          {/* Audit Verification Alert Banner */}
          {auditResult && (
            <div
              className="card"
              style={{
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '8px',
                fontSize: '0.82rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <FileCheck2 size={16} color="#ffffff" />
                <span>
                  <strong>Audit Status:</strong> {auditResult.details} ({auditResult.verified_events} verified events)
                </span>
              </div>
              <span className="badge badge-mono font-mono" style={{ fontSize: '0.7rem' }}>
                Head: {auditResult.chain_head_hash ? `${auditResult.chain_head_hash.slice(0, 12)}...` : 'None'}
              </span>
            </div>
          )}

          {auditError && (
            <div className="card" style={{ padding: '10px 14px', color: '#f5f5f5', border: '1px solid #737373', fontSize: '0.8rem' }}>
              {auditError}
            </div>
          )}

          {/* Two-Column Core Layout: 42% left / 58% right on desktop */}
          <div className="soc-workbench-grid" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 4.2fr) minmax(0, 5.8fr)', gap: '20px' }}>
            {/* LEFT COLUMN: Deterministic Findings & Triggered Policies */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', minWidth: 0 }}>
              {/* Findings Panel */}
              <div className="card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldAlert size={16} color="#ffffff" strokeWidth={1.8} />
                    <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
                      Detected Entities ({result.counts.total})
                    </h3>
                  </div>
                  <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                    {result.processing_duration_ms} ms
                  </span>
                </div>

                {result.findings.length === 0 ? (
                  <div style={{ padding: '32px 16px', textAlign: 'center', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)' }}>
                    <ShieldCheck size={28} color="#ffffff" style={{ margin: '0 auto 8px', opacity: 0.8 }} />
                    <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>Zero Sensitive Entities Detected</div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      No credentials, private tokens, or customer personal identifiers detected.
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '460px', overflowY: 'auto' }}>
                    {result.findings.map((f: Finding) => (
                      <div
                        key={f.id}
                        style={{
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '12px 14px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {renderSeverityBadge(f.severity)}
                            <span className="badge badge-mono" style={{ fontSize: '0.66rem' }}>
                              {f.category}
                            </span>
                          </div>
                          <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                            conf: {(f.confidence * 100).toFixed(0)}%
                          </span>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', gap: '8px' }}>
                          <span style={{ fontSize: '0.84rem', fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                            {f.rule_id}
                          </span>
                          <span className="font-mono text-muted" style={{ fontSize: '0.7rem', flexShrink: 0 }}>
                            [{f.start_offset}:{f.end_offset}]
                          </span>
                        </div>

                        {/* Masked Evidence */}
                        <div
                          className="font-mono"
                          style={{
                            background: '#0c0c0c',
                            padding: '6px 10px',
                            borderRadius: 'var(--radius-xs)',
                            fontSize: '0.76rem',
                            color: 'var(--text-primary)',
                            marginBottom: '6px',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            border: '1px solid var(--border-subtle)',
                            wordBreak: 'break-all',
                          }}
                        >
                          <Lock size={11} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                          <span>Evidence: {f.masked_evidence}</span>
                        </div>

                        <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
                          {f.suggested_remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Triggered Policies Panel */}
              {result.triggered_policies && result.triggered_policies.length > 0 && (
                <div className="card" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                    <Layers size={16} color="#ffffff" strokeWidth={1.8} />
                    <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>
                      Triggered Policy Rules ({result.triggered_policies.length})
                    </h3>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {result.triggered_policies.map((p) => (
                      <div
                        key={p.id}
                        style={{
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '12px 14px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px', gap: '8px' }}>
                          <div>
                            <span className="font-mono text-primary" style={{ fontSize: '0.8rem', fontWeight: 700, marginRight: '8px' }}>
                              {p.id}
                            </span>
                            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                              {p.name}
                            </span>
                            {p.org_id && p.org_id !== 'default' && (
                              <span className="badge badge-outline" style={{ fontSize: '0.62rem', marginLeft: '6px' }}>
                                Org: {p.org_id}
                              </span>
                            )}
                          </div>
                          <span className="badge badge-mono" style={{ flexShrink: 0 }}>{p.action}</span>
                        </div>
                        <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginBottom: '4px', lineHeight: 1.4 }}>
                          {p.description}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                          Intent: {p.intent_explanation}
                        </div>
                        {result.ai_analysis?.policy_rationales && result.ai_analysis.policy_rationales[p.id] && (
                          <div style={{ fontSize: '0.74rem', color: '#93c5fd', marginTop: '6px', background: 'rgba(59, 130, 246, 0.08)', padding: '6px 10px', borderRadius: 'var(--radius-sm)', borderLeft: '3px solid #3b82f6', lineHeight: 1.4 }}>
                            <span style={{ fontWeight: 600, color: '#bfdbfe' }}>Policy Rationale:</span> {result.ai_analysis.policy_rationales[p.id]}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* RIGHT COLUMN: Redacted Text Preview & Advisory AI Context Analysis */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', minWidth: 0 }}>
              {/* Redacted Preview */}
              <div className="card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Eye size={16} color="#ffffff" strokeWidth={1.8} />
                    <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>
                      Non-Destructive Redacted Output
                    </h3>
                  </div>
                  <button
                    className="btn-secondary"
                    onClick={handleCopyRedacted}
                    style={{ fontSize: '0.76rem', padding: '4px 10px' }}
                  >
                    {copied ? (
                      <>
                        <Check size={12} />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy size={12} />
                        <span>Copy Redacted</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Monospaced Code Panel */}
                <div
                  className="font-mono card-inset"
                  style={{
                    padding: '14px',
                    fontSize: '0.8rem',
                    lineHeight: 1.5,
                    color: 'var(--text-primary)',
                    maxHeight: '280px',
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {result.redacted_text}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '8px' }}>
                  Deterministic redaction preserves payload syntax while eliminating raw secrets and sensitive tokens.
                </div>
              </div>

              {/* Advisory AI Context Analysis Panel */}
              {result.ai_analysis && (
                <div className="card ai-analysis-card">
                  {/* Header Row: Heading, Icon, and Gemini Active status badge on the same horizontal row */}
                  <div className="ai-header-row">
                    <div className="ai-header-title-group">
                      <Bot size={16} color="#ffffff" strokeWidth={1.8} className="ai-header-icon" />
                      <h3 className="ai-header-title">
                        Advisory AI Context Analysis
                      </h3>
                    </div>

                    <span className="badge badge-mono ai-header-badge">
                      {result.ai_analysis.is_ai_assisted
                        ? `Gemini Active (${result.ai_analysis.model_identifier || 'gemini-3.1-flash-lite'})`
                        : `Fallback Mode (${result.ai_analysis.ai_status})`}
                    </span>
                  </div>

                  <div className="ai-content-layout">
                    {/* Full-width Context Assessment Panel */}
                    <div className="ai-panel ai-context-panel">
                      <div className="ai-panel-label">
                        Context Assessment
                      </div>
                      <div className="ai-context-summary">
                        {result.ai_analysis.incident_summary || 'Context analysis complete.'}
                      </div>
                      {Array.isArray(result.ai_analysis.ambiguities_and_uncertainty) && result.ai_analysis.ambiguities_and_uncertainty.length > 0 && (
                        <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid var(--border-subtle)' }}>
                          <div style={{ fontSize: '0.68rem', fontWeight: 600, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
                            Contextual Ambiguities & Uncertainty
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                            {result.ai_analysis.ambiguities_and_uncertainty.map((amb, idx) => (
                              <div key={idx} style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
                                <span style={{ color: '#f59e0b', flexShrink: 0 }}>⚠️</span>
                                <span>{amb}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Two-Column Row: Human Review Advised & Identified Risk Factors */}
                    <div className="ai-two-column-row">
                      {/* Left: Human Review Status Card */}
                      <div className="ai-panel ai-review-card">
                        <div className="ai-panel-label">
                          Human Review Recommendation
                        </div>
                        <div className="ai-review-content">
                          <div className="ai-review-icon-wrap">
                            {result.ai_analysis.human_review_recommended ? (
                              <UserCheck size={18} color="#ffffff" />
                            ) : (
                              <CheckCircle2 size={18} color="var(--text-muted)" />
                            )}
                          </div>
                          <div className="ai-review-text-group">
                            <div className="ai-review-headline">
                              {result.ai_analysis.human_review_recommended ? 'Human Review Advised' : 'Automated Clearance'}
                            </div>
                            <div className="ai-review-subtext">
                              {result.ai_analysis.human_review_recommended ? 'Analyst sign-off required' : 'Low risk profile'}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Right: Identified Risk Factors Card */}
                      <div className="ai-panel ai-risk-card">
                        <div className="ai-panel-label">
                          Identified Risk Factors
                        </div>
                        <div className="ai-risk-factors-content">
                          {Array.isArray(result.ai_analysis.relevant_risk_factors) && result.ai_analysis.relevant_risk_factors.length > 0 ? (
                            <div className="ai-risk-badges-wrap">
                              {result.ai_analysis.relevant_risk_factors.map((rf, idx) => (
                                <span key={idx} className="badge badge-mono ai-risk-badge">
                                  {rf}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <div className="ai-empty-text">
                              Standard risk baseline — no elevated contextual risk factors detected
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Policy Explanation Panel */}
                    {result.ai_analysis.policy_rationales && Object.keys(result.ai_analysis.policy_rationales).length > 0 && (
                      <div className="ai-panel ai-policy-panel">
                        <div className="ai-panel-label">
                          Policy Explanations ({Object.keys(result.ai_analysis.policy_rationales).length})
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                          {Object.entries(result.ai_analysis.policy_rationales).map(([pid, rationale]) => (
                            <div key={pid} style={{ fontSize: '0.8rem', lineHeight: 1.4, padding: '8px 10px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 'var(--radius-sm)', borderLeft: '3px solid #3b82f6' }}>
                              <span className="font-mono" style={{ color: '#60a5fa', fontWeight: 600, marginRight: '8px' }}>{pid}:</span>
                              <span style={{ color: 'var(--text-secondary)' }}>{rationale}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Full-width Advisory Remediation Section */}
                    {Array.isArray(result.ai_analysis.remediation_recommendations) && result.ai_analysis.remediation_recommendations.length > 0 && (
                      <div className="ai-remediation-section">
                        <div className="ai-panel-label" style={{ marginBottom: '8px' }}>
                          Advisory Remediation ({result.ai_analysis.remediation_recommendations.length})
                        </div>

                        <div className="ai-remediation-list">
                          {result.ai_analysis.remediation_recommendations.map((rec) => (
                            <div key={rec.id} className="ai-remediation-card">
                              <div className="ai-remediation-header">
                                <div className="ai-remediation-title-group">
                                  <ShieldAlert size={14} color="#ffffff" style={{ flexShrink: 0 }} />
                                  <span className="ai-remediation-title">
                                    {rec.title}
                                  </span>
                                </div>
                                <span className="badge badge-outline ai-remediation-badge">
                                  {(rec.action_type || 'ADVISORY').replace(/_/g, ' ')}
                                </span>
                              </div>
                              <div className="ai-remediation-explanation">
                                {rec.explanation}
                              </div>
                              {rec.reason && (
                                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                                  <span style={{ opacity: 0.8 }}>Justification:</span> {rec.reason}
                                </div>
                              )}
                              <div className="ai-remediation-benefit">
                                <span style={{ opacity: 0.8 }}>Expected Benefit:</span> {rec.expected_security_benefit}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Usage & Reliability Telemetry */}
                    {result.ai_analysis.usage && (
                      <div style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: '12px',
                        alignItems: 'center',
                        padding: '8px 12px',
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.72rem',
                        color: 'var(--text-muted)',
                      }}>
                        <span>
                          <strong style={{ color: 'var(--text-secondary)' }}>Request Model:</strong> 1 shared API call ({result.ai_analysis.usage.operation})
                        </span>
                        {result.ai_analysis.usage.prompt_tokens !== null && result.ai_analysis.usage.prompt_tokens !== undefined ? (
                          <span>
                            <strong style={{ color: 'var(--text-secondary)' }}>Tokens:</strong> {result.ai_analysis.usage.prompt_tokens} in / {result.ai_analysis.usage.candidates_tokens || 0} out ({result.ai_analysis.usage.total_tokens || 0} total)
                            {result.ai_analysis.usage.cached_tokens ? ` [${result.ai_analysis.usage.cached_tokens} cached]` : ''}
                            <span style={{ color: '#10b981', marginLeft: '4px' }}>[Provider Confirmed]</span>
                          </span>
                        ) : (
                          <span>
                            <strong style={{ color: 'var(--text-secondary)' }}>Tokens:</strong> N/A (0 live tokens consumed)
                          </span>
                        )}
                        {result.ai_analysis.usage.latency_ms !== null && result.ai_analysis.usage.latency_ms !== undefined && (
                          <span>
                            <strong style={{ color: 'var(--text-secondary)' }}>Latency:</strong> {(result.ai_analysis.usage.latency_ms / 1000).toFixed(2)}s
                          </span>
                        )}
                        {result.ai_analysis.usage.retries_attempted > 0 && (
                          <span style={{ color: '#f59e0b' }}>
                            <strong>Retries:</strong> {result.ai_analysis.usage.retries_attempted}
                          </span>
                        )}
                        {result.ai_analysis.usage.rate_limit_encountered && (
                          <span style={{ color: '#ef4444' }}>
                            [429 Rate Limit Encountered]
                          </span>
                        )}
                      </div>
                    )}

                    {/* Legal/Architectural Invariance Disclaimer */}
                    <div className="ai-disclaimer-footer">
                      {result.ai_analysis.disclaimer}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @media (max-width: 1024px) {
          .soc-workbench-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
};

const InfoBadge: React.FC<{ note: string }> = ({ note }) => (
  <span>📄 {note}</span>
);
