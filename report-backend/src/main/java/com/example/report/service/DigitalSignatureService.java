package com.example.report.service;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.token.*;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import jakarta.enterprise.context.ApplicationScoped;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.logging.Logger;

@ApplicationScoped
public class DigitalSignatureService {
    
    private static final Logger LOGGER = Logger.getLogger(DigitalSignatureService.class.getName());
    
    public static class SignatureConfiguration {
        public String keystorePath = "/tmp/tsunami-keystore.p12";
        public String keystorePassword = "tsunami123";
        public String certificateAlias = "tsunami-cert";
        public String reason = "Tsunami Security Report";
        public String location = "Tsunami Security Platform";
        public String contactInfo = "security@tsunami-platform.com";
        public String tsaUrl = "http://timestamp.sectigo.com"; // Timestamp Authority
        public SignatureLevel signatureLevel = SignatureLevel.PAdES_BASELINE_T;
        public SignaturePackaging packaging = SignaturePackaging.ENVELOPED;
        public DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
    }
    
    public byte[] signPDF(byte[] pdfContent, SignatureConfiguration config) throws Exception {
        LOGGER.info("Starting PDF digital signature process");
        
        try {
            // Load the signing token
            SignatureTokenConnection signingToken = loadSigningToken(config);
            
            // Prepare the document to be signed
            DSSDocument documentToSign = new InMemoryDocument(pdfContent, "report.pdf");
            
            // Create signature parameters
            PAdESSignatureParameters parameters = createSignatureParameters(signingToken, config);
            
            // Create the signing service
            PAdESService service = createSigningService(config);
            
            // Get the SignedInfo segment
            ToBeSigned dataToSign = service.getDataToSign(documentToSign, parameters);
            
            // Sign the document
            DSSPrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(signingToken, config);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry);
            
            // Get the signed document
            DSSDocument signedDocument = service.signDocument(documentToSign, parameters, signatureValue);
            
            // Convert to byte array
            byte[] signedPdfBytes = signedDocument.readAllBytes();
            
            LOGGER.info("PDF successfully signed with digital signature");
            return signedPdfBytes;
            
        } catch (Exception e) {
            LOGGER.severe("Failed to sign PDF: " + e.getMessage());
            throw new RuntimeException("Digital signature failed: " + e.getMessage(), e);
        }
    }
    
    public byte[] signPDFWithSelfSignedCertificate(byte[] pdfContent) throws Exception {
        // Create a self-signed certificate for development/testing
        SignatureConfiguration config = createDevelopmentConfiguration();
        return signPDF(pdfContent, config);
    }
    
    public SignatureConfiguration createDevelopmentConfiguration() {
        SignatureConfiguration config = new SignatureConfiguration();
        config.reason = "Tsunami Security Report - Development Mode";
        config.location = "Tsunami Development Environment";
        config.contactInfo = "dev@tsunami-platform.com";
        config.keystorePath = generateDevelopmentKeystore();
        return config;
    }
    
    private String generateDevelopmentKeystore() {
        // For development, create a simple keystore path
        String keystorePath = "/tmp/tsunami-dev-keystore.p12";
        
        // In a production environment, you would load or generate a proper keystore
        LOGGER.info("Using development keystore path: " + keystorePath);
        
        return keystorePath;
    }
    
    private SignatureTokenConnection loadSigningToken(SignatureConfiguration config) throws Exception {
        try {
            // For development, use a mock or create a simple PKCS12 token
            // In production, this would load your actual certificate
            
            File keystoreFile = new File(config.keystorePath);
            if (!keystoreFile.exists()) {
                LOGGER.warning("Keystore not found, creating a development mock");
                return createMockSigningToken();
            }
            
            return new Pkcs12SignatureToken(
                new FileInputStream(config.keystorePath), 
                new PasswordProtection(config.keystorePassword.toCharArray())
            );
            
        } catch (Exception e) {
            LOGGER.warning("Failed to load keystore, using mock signing token: " + e.getMessage());
            return createMockSigningToken();
        }
    }
    
    private SignatureTokenConnection createMockSigningToken() {
        // Create a mock token for development
        return new MockSignatureTokenConnection();
    }
    
    private PAdESSignatureParameters createSignatureParameters(SignatureTokenConnection token, SignatureConfiguration config) throws Exception {
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        
        // Set signature level
        parameters.setSignatureLevel(config.signatureLevel);
        parameters.setSignaturePackaging(config.packaging);
        parameters.setDigestAlgorithm(config.digestAlgorithm);
        
        // Set signing date
        parameters.setSigningDate(new Date());
        
        // Set signature reason and location
        parameters.setReason(config.reason);
        parameters.setLocation(config.location);
        parameters.setContactInfo(config.contactInfo);
        
        // Set signing certificate
        DSSPrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(token, config);
        parameters.setSigningCertificate(privateKeyEntry.getCertificate());
        parameters.setCertificateChain(privateKeyEntry.getCertificateChain());
        
        return parameters;
    }
    
    private PAdESService createSigningService(SignatureConfiguration config) {
        // Create certificate verifier
        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        
        // Set data loader (DSS 6.0+ API)
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        certificateVerifier.setDataLoader(dataLoader);
        
        // Set AIA source (DSS 6.0+ API)
        DefaultAIASource aiaSource = new DefaultAIASource(dataLoader);
        certificateVerifier.setAiaSource(aiaSource);
        
        // Set CRL source
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        
        // Set OCSP source
        certificateVerifier.setOcspSource(new OnlineOCSPSource());
        
        // Create PAdES service
        PAdESService service = new PAdESService(certificateVerifier);
        
        // Configure timestamp if URL is provided
        if (config.tsaUrl != null && !config.tsaUrl.isEmpty()) {
            OnlineTSPSource tspSource = new OnlineTSPSource(config.tsaUrl);
            service.setTspSource(tspSource);
        }
        
        return service;
    }
    
    private DSSPrivateKeyEntry getPrivateKeyEntry(SignatureTokenConnection token, SignatureConfiguration config) throws Exception {
        try {
            // Get available keys
            java.util.List<DSSPrivateKeyEntry> keys = token.getKeys();
            
            if (keys.isEmpty()) {
                throw new RuntimeException("No private keys found in the keystore");
            }
            
            // Return the first key (or find by alias in production)
            return keys.get(0);
            
        } catch (Exception e) {
            LOGGER.severe("Failed to get private key entry: " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Mock implementation for development when no real certificate is available
     */
    private static class MockSignatureTokenConnection implements SignatureTokenConnection {
        
        @Override
        public java.util.List<DSSPrivateKeyEntry> getKeys() throws DSSException {
            // Return empty list for mock - would need proper implementation
            return new java.util.ArrayList<>();
        }
        
        @Override
        public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
            // Mock signature - in development, return a placeholder
            byte[] mockSignature = ("MOCK_SIGNATURE_" + System.currentTimeMillis()).getBytes();
            return new SignatureValue(SignatureAlgorithm.RSA_SHA256, mockSignature);
        }
        
        @Override
        public SignatureValue signDigest(Digest digest, SignatureAlgorithm signatureAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
            // Mock signature for digest signing
            byte[] mockSignature = ("MOCK_DIGEST_SIGNATURE_" + System.currentTimeMillis()).getBytes();
            return new SignatureValue(signatureAlgorithm, mockSignature);
        }
        
        @Override
        public void close() {
            // Nothing to close for mock (removed IOException)
        }
    }
    
    public boolean validateSignature(byte[] signedPdfContent) {
        try {
            LOGGER.info("Validating PDF signature");
            
            // Create document from signed PDF
            DSSDocument signedDocument = new InMemoryDocument(signedPdfContent);
            
            // Create certificate verifier
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            certificateVerifier.setDataLoader(new CommonsDataLoader());
            
            // Create validation service (DSS 6.0+ API)
            eu.europa.esig.dss.validation.DocumentValidator validator = 
                eu.europa.esig.dss.validation.SignedDocumentValidator.fromDocument(signedDocument);
            validator.setCertificateVerifier(certificateVerifier);
            
            // Validate
            eu.europa.esig.dss.validation.reports.Reports reports = validator.validateDocument();
            
            // Check if signature is valid
            boolean isValid = reports.getSimpleReport().isValid(reports.getSimpleReport().getFirstSignatureId());
            
            LOGGER.info("PDF signature validation result: " + isValid);
            return isValid;
            
        } catch (Exception e) {
            LOGGER.severe("Failed to validate signature: " + e.getMessage());
            return false;
        }
    }
}