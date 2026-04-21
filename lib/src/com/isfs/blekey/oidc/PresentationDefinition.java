/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.credential.VerifiableCredential;
import com.isfs.blekey.util.JsonUtils;
import com.isfs.blekey.util.http.HttpClient;
import com.isfs.blekey.util.http.HttpException;
import com.isfs.blekey.util.http.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Represents a DIF Presentation Exchange presentation definition.
 * 
 * A presentation definition describes what credentials and claims
 * a verifier requires from the holder.
 * 
 * Structure:
 * {
 *   "id": "example_presentation_definition",
 *   "input_descriptors": [
 *     {
 *       "id": "id_credential",
 *       "format": { "jwt_vc_json": {...} },
 *       "constraints": {
 *         "fields": [
 *           { "path": ["$.vc.type"], "filter": {...} }
 *         ]
 *       }
 *     }
 *   ]
 * }
 */
public class PresentationDefinition {
    
    private static final Logger logger = LoggerFactory.getLogger(PresentationDefinition.class);
    
    private String id;
    private List<InputDescriptor> inputDescriptors;
    
    public PresentationDefinition() {
        this.inputDescriptors = new ArrayList<>();
    }
    
    /**
     * Parses a presentation definition from JSON.
     * 
     * @param json The JSON string
     * @return Parsed PresentationDefinition
     * @throws OidcException if parsing fails
     */
    public static PresentationDefinition fromJson(String json) throws OidcException {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) JsonUtils.decode(json, Map.class);
            return fromMap(map);
        } catch (Exception e) {
            logger.error("Failed to parse presentation definition", e);
            throw new OidcException("Failed to parse presentation definition: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses a presentation definition from a map.
     * 
     * @param map The map representation
     * @return Parsed PresentationDefinition
     * @throws OidcException if parsing fails
     */
    @SuppressWarnings("unchecked")
    public static PresentationDefinition fromMap(Map<String, Object> map) throws OidcException {
        if (map == null) {
            throw new OidcException("Presentation definition map is null");
        }
        
        PresentationDefinition def = new PresentationDefinition();
        
        def.id = (String) map.get("id");
        
        List<Map<String, Object>> descriptorMaps = (List<Map<String, Object>>) map.get("input_descriptors");
        if (descriptorMaps != null) {
            for (Map<String, Object> descriptorMap : descriptorMaps) {
                def.inputDescriptors.add(InputDescriptor.fromMap(descriptorMap));
            }
        }
        
        logger.debug("Parsed presentation definition: id={}, descriptors={}", 
                    def.id, def.inputDescriptors.size());
        
        return def;
    }
    
    /**
     * Fetches and parses a presentation definition from a URI.
     *
     * @param uri The URI to fetch the presentation definition from
     * @return Parsed PresentationDefinition
     * @throws OidcException if fetching or parsing fails
     */
    public static PresentationDefinition fromUri(String uri) throws OidcException {
        try {
            HttpClient httpClient = new HttpClient();
            HttpResponse response = httpClient.get(uri);
            
            if (!response.isSuccessful()) {
                throw new OidcException("Failed to fetch presentation definition: HTTP " + response.getStatusCode());
            }
            
            String contentType = response.getHeader("Content-Type");
            String body = response.getBody();
            
            if (contentType != null && contentType.contains("application/jwt")) {
                return fromJwt(body);
            } else {
                return fromJson(body);
            }
        } catch (HttpException e) {
            logger.error("HTTP error fetching presentation definition", e);
            throw new OidcException("Failed to fetch presentation definition: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Failed to fetch presentation definition from URI", e);
            throw new OidcException("Failed to fetch presentation definition: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parses a presentation definition from a JWT.
     *
     * @param jwt The JWT string
     * @return Parsed PresentationDefinition
     * @throws OidcException if parsing fails
     */
    private static PresentationDefinition fromJwt(String jwt) throws OidcException {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                throw new OidcException("Invalid JWT format: expected at least 2 parts");
            }
            
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) JsonUtils.decode(payload, Map.class);
            
            Object pdObj = claims.get("presentation_definition");
            if (pdObj == null) {
                throw new OidcException("JWT does not contain 'presentation_definition' claim");
            }
            
            if (!(pdObj instanceof Map)) {
                throw new OidcException("'presentation_definition' claim is not a map");
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> pdMap = (Map<String, Object>) pdObj;
            return fromMap(pdMap);
        } catch (IllegalArgumentException e) {
            throw new OidcException("Failed to decode JWT: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new OidcException("Failed to parse JWT presentation definition", e);
        }
    }
    
    /**
     * Checks if a credential matches this presentation definition.
     *
     * @param credential The credential to check
     * @return true if the credential matches, false otherwise
     */
    public boolean matches(VerifiableCredential credential) {
        if (credential == null || inputDescriptors == null || inputDescriptors.isEmpty()) {
            return false;
        }
        
        for (InputDescriptor descriptor : inputDescriptors) {
            if (matchesDescriptor(credential, descriptor)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Checks if a credential matches a specific input descriptor.
     */
    private boolean matchesDescriptor(VerifiableCredential credential, InputDescriptor descriptor) {
        if (descriptor.getConstraints() == null) {
            return true;
        }
        
        List<Field> fields = descriptor.getConstraints().getFields();
        if (fields == null || fields.isEmpty()) {
            return true;
        }
        
        for (Field field : fields) {
            if (!matchesField(credential, field)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Checks if a credential matches a specific field constraint.
     */
    private boolean matchesField(VerifiableCredential credential, Field field) {
        if (field.getPath() == null || field.getPath().isEmpty()) {
            return true;
        }
        
        String path = field.getPath().get(0);
        
        if (path.contains("$.vc.type") || path.contains("type")) {
            String credentialType = credential.getMetadata().getCredentialType();
            if (credentialType == null) {
                return false;
            }
            
            if (field.getFilter() != null) {
                Object pattern = field.getFilter().get("pattern");
                if (pattern != null) {
                    return credentialType.matches(pattern.toString());
                }
                
                Object contains = field.getFilter().get("contains");
                if (contains != null) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> containsMap = (Map<String, Object>) contains;
                    Object constValue = containsMap.get("const");
                    if (constValue != null) {
                        return credentialType.contains(constValue.toString());
                    }
                }
            }
            
            return true;
        }
        
        return true;
    }
    
    /**
     * Gets the verifier name from the presentation definition.
     *
     * @return Verifier name, or "Unknown Verifier" if not available
     */
    public String getVerifierName() {
        if (inputDescriptors != null && !inputDescriptors.isEmpty()) {
            InputDescriptor firstDescriptor = inputDescriptors.get(0);
            if (firstDescriptor.getId() != null) {
                return formatVerifierName(firstDescriptor.getId());
            }
        }
        
        if (id != null) {
            return formatVerifierName(id);
        }
        
        return "Unknown Verifier";
    }
    
    /**
     * Formats a verifier name from an ID string.
     */
    private String formatVerifierName(String id) {
        String formatted = id.replace("_", " ").replace("-", " ");
        
        String[] words = formatted.split("\\s+");
        StringBuilder result = new StringBuilder();
        
        for (String word : words) {
            if (word.length() > 0) {
                result.append(Character.toUpperCase(word.charAt(0)));
                if (word.length() > 1) {
                    result.append(word.substring(1).toLowerCase());
                }
                result.append(" ");
            }
        }
        
        return result.toString().trim();
    }
    
    /**
     * Gets the list of requested field names from the presentation definition.
     *
     * @return List of requested field names
     */
    public List<String> getRequestedFields() {
        List<String> fields = new ArrayList<>();
        
        if (inputDescriptors == null) {
            return fields;
        }
        
        for (InputDescriptor descriptor : inputDescriptors) {
            if (descriptor.getConstraints() != null &&
                descriptor.getConstraints().getFields() != null) {
                
                for (Field field : descriptor.getConstraints().getFields()) {
                    if (field.getPath() != null && !field.getPath().isEmpty()) {
                        String path = field.getPath().get(0);
                        String fieldName = extractFieldName(path);
                        if (fieldName != null && !fields.contains(fieldName)) {
                            fields.add(fieldName);
                        }
                    }
                }
            }
        }
        
        return fields;
    }
    
    /**
     * Extracts a human-readable field name from a JSON path.
     */
    private String extractFieldName(String path) {
        String cleaned = path.replaceAll("\\$\\.|\\[.*?\\]", "");
        
        String[] parts = cleaned.split("\\.");
        if (parts.length > 0) {
            String lastPart = parts[parts.length - 1];
            
            String formatted = lastPart.replace("_", " ").replace("-", " ");
            String[] words = formatted.split("\\s+");
            StringBuilder result = new StringBuilder();
            
            for (String word : words) {
                if (word.length() > 0) {
                    result.append(Character.toUpperCase(word.charAt(0)));
                    if (word.length() > 1) {
                        result.append(word.substring(1).toLowerCase());
                    }
                    result.append(" ");
                }
            }
            
            return result.toString().trim();
        }
        
        return null;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public List<InputDescriptor> getInputDescriptors() {
        return inputDescriptors;
    }
    
    public void setInputDescriptors(List<InputDescriptor> inputDescriptors) {
        this.inputDescriptors = inputDescriptors;
    }
    
    /**
     * Represents an input descriptor within a presentation definition.
     */
    public static class InputDescriptor {
        private String id;
        private Map<String, Object> format;
        private Constraints constraints;
        
        @SuppressWarnings("unchecked")
        public static InputDescriptor fromMap(Map<String, Object> map) {
            InputDescriptor descriptor = new InputDescriptor();
            descriptor.id = (String) map.get("id");
            descriptor.format = (Map<String, Object>) map.get("format");
            
            Map<String, Object> constraintsMap = (Map<String, Object>) map.get("constraints");
            if (constraintsMap != null) {
                descriptor.constraints = Constraints.fromMap(constraintsMap);
            }
            
            return descriptor;
        }
        
        public String getId() {
            return id;
        }
        
        public Map<String, Object> getFormat() {
            return format;
        }
        
        public Constraints getConstraints() {
            return constraints;
        }
    }
    
    /**
     * Represents constraints on credential selection.
     */
    public static class Constraints {
        private List<Field> fields;
        
        @SuppressWarnings("unchecked")
        public static Constraints fromMap(Map<String, Object> map) {
            Constraints constraints = new Constraints();
            constraints.fields = new ArrayList<>();
            
            List<Map<String, Object>> fieldMaps = (List<Map<String, Object>>) map.get("fields");
            if (fieldMaps != null) {
                for (Map<String, Object> fieldMap : fieldMaps) {
                    constraints.fields.add(Field.fromMap(fieldMap));
                }
            }
            
            return constraints;
        }
        
        public List<Field> getFields() {
            return fields;
        }
    }
    
    /**
     * Represents a field constraint.
     */
    public static class Field {
        private List<String> path;
        private Map<String, Object> filter;
        
        @SuppressWarnings("unchecked")
        public static Field fromMap(Map<String, Object> map) {
            Field field = new Field();
            field.path = (List<String>) map.get("path");
            field.filter = (Map<String, Object>) map.get("filter");
            return field;
        }
        
        public List<String> getPath() {
            return path;
        }
        
        public Map<String, Object> getFilter() {
            return filter;
        }
    }
}

// Made with Bob