import React, { useState, useRef, useEffect } from 'react';
import { Upload, X, AlertCircle, FileCheck, Trash2 } from 'lucide-react';
import { uploadApk, startPassiveAnalysis, startActiveAnalysis } from '../services/api';

export default function UploadModal({ isOpen, onClose, mode = 'passive', onJobStarted }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  // Full reset function to explicitly clear file input, cache, and component state
  const resetFormState = () => {
    setSelectedFile(null);
    setError(null);
    setLoading(false);
    setDragActive(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Whenever modal opens, closes, or analysis mode changes, ensure completely clean state
  useEffect(() => {
    resetFormState();
    return () => {
      resetFormState();
    };
  }, [isOpen, mode]);

  if (!isOpen) return null;

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelection(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelection = (file) => {
    setError(null);
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.apk')) {
      setError('Invalid file type. Please upload a valid Android APK file (.apk).');
      resetFormState();
      return;
    }
    if (file.size > 100 * 1024 * 1024) {
      setError('File size exceeds the 100 MB limit.');
      resetFormState();
      return;
    }
    setSelectedFile(file);
  };

  const handleRemoveFile = (e) => {
    if (e) {
      e.stopPropagation();
    }
    resetFormState();
  };

  const handleClose = () => {
    resetFormState();
    onClose();
  };

  const handleSubmit = async () => {
    if (!selectedFile) return;

    setLoading(true);
    setError(null);

    try {
      // 1. Upload & Validate
      const uploadResult = await uploadApk(selectedFile);
      const jobId = uploadResult.job_id;

      // 2. Start specific analysis mode
      if (mode === 'active') {
        await startActiveAnalysis(jobId);
      } else {
        await startPassiveAnalysis(jobId);
      }

      onJobStarted({
        jobId,
        filename: selectedFile.name,
        mode,
        fileHash: uploadResult.file_hash,
        fileSize: uploadResult.file_size
      });

      // Explicitly clear file input and form cache immediately on success
      resetFormState();
      onClose();
    } catch (err) {
      setError(err.message || 'Analysis initiation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={handleClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '20px', fontWeight: '700', color: '#FFFFFF' }}>
              {mode === 'active' ? 'Start Active Analysis' : 'Start Passive Analysis'}
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              {mode === 'active' 
                ? 'Executes the APK inside an isolated Android emulator sandbox.'
                : 'Extracts manifest, permissions, DEX opcodes, and static features without running.'}
            </p>
          </div>
          <button 
            onClick={handleClose} 
            style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
            title="Close"
          >
            <X size={20} />
          </button>
        </div>

        {error && (
          <div style={{ 
            background: 'var(--status-malicious-bg)', 
            border: '1px solid var(--status-malicious-border)', 
            borderRadius: '12px', 
            padding: '12px 16px', 
            display: 'flex', 
            alignItems: 'center', 
            gap: '10px', 
            marginBottom: '16px',
            color: '#F87171',
            fontSize: '13px'
          }}>
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        <div 
          className={`drop-zone ${dragActive ? 'active' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => {
            if (fileInputRef.current) {
              fileInputRef.current.value = '';
              fileInputRef.current.click();
            }
          }}
        >
          <input 
            type="file" 
            ref={fileInputRef} 
            accept=".apk" 
            style={{ display: 'none' }} 
            onClick={(e) => {
              // Crucial: clears cached value so selecting the exact same file fresh fires onChange
              e.target.value = '';
            }}
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileSelection(e.target.files[0]);
              }
            }}
          />

          {selectedFile ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '14px', background: 'rgba(16, 185, 129, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10B981' }}>
                <FileCheck size={28} />
              </div>
              <span style={{ fontWeight: '600', color: '#FFFFFF', fontSize: '14px' }}>{selectedFile.name}</span>
              <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                {(selectedFile.size / 1024 / 1024).toFixed(2)} MB • Ready for analysis
              </span>
              
              <button
                type="button"
                onClick={handleRemoveFile}
                style={{
                  marginTop: '8px',
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  color: '#F87171',
                  borderRadius: '8px',
                  padding: '5px 12px',
                  fontSize: '12px',
                  fontWeight: '600',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  transition: 'background 0.2s'
                }}
                title="Remove selected APK file"
              >
                <Trash2 size={13} />
                <span>Remove File</span>
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '14px', background: 'rgba(59, 130, 246, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-blue)' }}>
                <Upload size={24} />
              </div>
              <div>
                <span style={{ fontWeight: '600', color: '#FFFFFF', fontSize: '14px' }}>Click to select APK</span>
                <span style={{ color: 'var(--text-secondary)', fontSize: '14px' }}> or drag and drop</span>
              </div>
              <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Maximum APK package size: 100 MB</span>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px', marginTop: '24px' }}>
          <button 
            type="button" 
            className="btn-secondary" 
            onClick={handleClose}
            disabled={loading}
          >
            Cancel
          </button>
          <button 
            type="button" 
            className="btn-primary" 
            onClick={handleSubmit}
            disabled={!selectedFile || loading}
            style={{ opacity: (!selectedFile || loading) ? 0.6 : 1 }}
          >
            {loading ? 'Initiating Pipeline...' : `Run ${mode === 'active' ? 'Active' : 'Passive'} Analysis`}
          </button>
        </div>
      </div>
    </div>
  );
}
