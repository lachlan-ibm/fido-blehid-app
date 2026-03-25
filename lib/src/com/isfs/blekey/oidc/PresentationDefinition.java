/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
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