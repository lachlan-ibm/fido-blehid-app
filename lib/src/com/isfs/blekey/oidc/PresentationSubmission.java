/*
 * Copyright IBM 2026
 */
package com.isfs.blekey.oidc;

import com.isfs.blekey.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a DIF Presentation Exchange presentation submission.
 * 
 * A presentation submission describes how the holder's credentials
 * satisfy the verifier's presentation definition.
 */
public class PresentationSubmission {
    
    private static final Logger logger = LoggerFactory.getLogger(PresentationSubmission.class);
    
    private String id;
    private String definitionId;
    private List<DescriptorMap> descriptorMap;
    
    public PresentationSubmission() {
        this.descriptorMap = new ArrayList<>();
    }
    
    /**
     * Creates a presentation submission for a single credential.
     */
    public static PresentationSubmission createSingle(String definitionId,
                                                     String descriptorId,
                                                     String format) {
        PresentationSubmission submission = new PresentationSubmission();
        submission.id = java.util.UUID.randomUUID().toString();
        submission.definitionId = definitionId;
        
        DescriptorMap descriptor = new DescriptorMap();
        descriptor.id = descriptorId;
        descriptor.format = format;
        descriptor.path = "$";
        
        submission.descriptorMap.add(descriptor);
        
        logger.debug("Created presentation submission: id={}, definitionId={}", 
                    submission.id, definitionId);
        
        return submission;
    }
    
    public String toJson() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", id);
        map.put("definition_id", definitionId);
        
        List<Map<String, Object>> descriptorMaps = new ArrayList<>();
        for (DescriptorMap desc : descriptorMap) {
            Map<String, Object> descMap = new HashMap<>();
            descMap.put("id", desc.id);
            descMap.put("format", desc.format);
            descMap.put("path", desc.path);
            if (desc.pathNested != null) {
                descMap.put("path_nested", desc.pathNested);
            }
            descriptorMaps.add(descMap);
        }
        map.put("descriptor_map", descriptorMaps);
        
        return JsonUtils.encode(map);
    }
    
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", id);
        map.put("definition_id", definitionId);
        
        List<Map<String, Object>> descriptorMaps = new ArrayList<>();
        for (DescriptorMap desc : descriptorMap) {
            Map<String, Object> descMap = new HashMap<>();
            descMap.put("id", desc.id);
            descMap.put("format", desc.format);
            descMap.put("path", desc.path);
            if (desc.pathNested != null) {
                descMap.put("path_nested", desc.pathNested);
            }
            descriptorMaps.add(descMap);
        }
        map.put("descriptor_map", descriptorMaps);
        
        return map;
    }
    
    public String getId() {
        return id;
    }
    
    public void setId(String id) {
        this.id = id;
    }
    
    public String getDefinitionId() {
        return definitionId;
    }
    
    public void setDefinitionId(String definitionId) {
        this.definitionId = definitionId;
    }
    
    public List<DescriptorMap> getDescriptorMap() {
        return descriptorMap;
    }
    
    public void setDescriptorMap(List<DescriptorMap> descriptorMap) {
        this.descriptorMap = descriptorMap;
    }
    
    public void addDescriptor(String descriptorId, String format, String path) {
        DescriptorMap descriptor = new DescriptorMap();
        descriptor.id = descriptorId;
        descriptor.format = format;
        descriptor.path = path;
        descriptorMap.add(descriptor);
    }
    
    public static class DescriptorMap {
        private String id;
        private String format;
        private String path;
        private String pathNested;
        
        public String getId() {
            return id;
        }
        
        public String getFormat() {
            return format;
        }
        
        public String getPath() {
            return path;
        }
        
        public String getPathNested() {
            return pathNested;
        }
        
        public void setPathNested(String pathNested) {
            this.pathNested = pathNested;
        }
    }
}

// Made with Bob