/*
 * Copyright IBM 2025, 2026
 */
package com.isfs.blekey.credential.jsonld;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JsonLdContext}.
 */
class JsonLdContextTest {
    
    private JsonLdContext context;
    
    @BeforeEach
    void setUp() {
        context = new JsonLdContext();
        JsonLdContext.clearCache();
    }
    
    @Test
    void testEmptyContext() {
        assertTrue(context.isEmpty());
        assertTrue(context.getContextUrls().isEmpty());
        assertTrue(context.getTermDefinitions().isEmpty());
    }
    
    @Test
    void testConstructorWithSingleUrl() {
        JsonLdContext ctx = new JsonLdContext(JsonLdContext.W3C_VC_CONTEXT);
        
        assertFalse(ctx.isEmpty());
        assertEquals(1, ctx.getContextUrls().size());
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, ctx.getContextUrls().get(0));
    }
    
    @Test
    void testConstructorWithMultipleUrls() {
        List<String> urls = Arrays.asList(
            JsonLdContext.W3C_VC_CONTEXT,
            "https://www.w3.org/2018/credentials/examples/v1"
        );
        JsonLdContext ctx = new JsonLdContext(urls);
        
        assertFalse(ctx.isEmpty());
        assertEquals(2, ctx.getContextUrls().size());
        assertEquals(urls, ctx.getContextUrls());
    }
    
    @Test
    void testAddContextUrl() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        
        assertFalse(context.isEmpty());
        assertEquals(1, context.getContextUrls().size());
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, context.getContextUrls().get(0));
    }
    
    @Test
    void testAddMultipleContextUrls() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        
        assertEquals(2, context.getContextUrls().size());
    }
    
    @Test
    void testAddNullContextUrl() {
        context.addContextUrl(null);
        assertTrue(context.isEmpty());
    }
    
    @Test
    void testAddEmptyContextUrl() {
        context.addContextUrl("");
        assertTrue(context.isEmpty());
    }
    
    @Test
    void testAddTermDefinition() {
        context.addTermDefinition("name", "http://schema.org/name");
        
        assertFalse(context.isEmpty());
        assertEquals(1, context.getTermDefinitions().size());
        assertEquals("http://schema.org/name", context.getTermDefinitions().get("name"));
    }
    
    @Test
    void testAddMultipleTermDefinitions() {
        context.addTermDefinition("name", "http://schema.org/name");
        context.addTermDefinition("email", "http://schema.org/email");
        
        assertEquals(2, context.getTermDefinitions().size());
        assertEquals("http://schema.org/name", context.getTermDefinitions().get("name"));
        assertEquals("http://schema.org/email", context.getTermDefinitions().get("email"));
    }
    
    @Test
    void testAddNullTermDefinition() {
        context.addTermDefinition(null, "http://schema.org/name");
        assertTrue(context.isEmpty());
        
        context.addTermDefinition("name", null);
        assertTrue(context.isEmpty());
    }
    
    @Test
    void testAddEmptyTermDefinition() {
        context.addTermDefinition("", "http://schema.org/name");
        assertTrue(context.isEmpty());
        
        context.addTermDefinition("name", "");
        assertTrue(context.isEmpty());
    }
    
    @Test
    void testToJsonSingleUrl() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        
        JsonElement json = context.toJson();
        assertTrue(json.isJsonPrimitive());
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, json.getAsString());
    }
    
    @Test
    void testToJsonMultipleUrls() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        
        JsonElement json = context.toJson();
        assertTrue(json.isJsonArray());
        
        JsonArray array = json.getAsJsonArray();
        assertEquals(2, array.size());
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, array.get(0).getAsString());
        assertEquals("https://www.w3.org/2018/credentials/examples/v1", array.get(1).getAsString());
    }
    
    @Test
    void testToJsonOnlyTerms() {
        context.addTermDefinition("name", "http://schema.org/name");
        context.addTermDefinition("email", "http://schema.org/email");
        
        JsonElement json = context.toJson();
        assertTrue(json.isJsonObject());
        
        JsonObject obj = json.getAsJsonObject();
        assertEquals(2, obj.size());
        assertEquals("http://schema.org/name", obj.get("name").getAsString());
        assertEquals("http://schema.org/email", obj.get("email").getAsString());
    }
    
    @Test
    void testToJsonUrlsAndTerms() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addTermDefinition("name", "http://schema.org/name");
        
        JsonElement json = context.toJson();
        assertTrue(json.isJsonArray());
        
        JsonArray array = json.getAsJsonArray();
        assertEquals(2, array.size());
        assertTrue(array.get(0).isJsonPrimitive());
        assertTrue(array.get(1).isJsonObject());
        
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, array.get(0).getAsString());
        JsonObject terms = array.get(1).getAsJsonObject();
        assertEquals("http://schema.org/name", terms.get("name").getAsString());
    }
    
    @Test
    void testFromJsonSingleUrl() throws JsonLdException {
        JsonElement json = new JsonPrimitive(JsonLdContext.W3C_VC_CONTEXT);
        JsonLdContext ctx = JsonLdContext.fromJson(json);
        
        assertEquals(1, ctx.getContextUrls().size());
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, ctx.getContextUrls().get(0));
    }
    
    @Test
    void testFromJsonArray() throws JsonLdException {
        JsonArray array = new JsonArray();
        array.add(JsonLdContext.W3C_VC_CONTEXT);
        array.add("https://www.w3.org/2018/credentials/examples/v1");
        
        JsonLdContext ctx = JsonLdContext.fromJson(array);
        
        assertEquals(2, ctx.getContextUrls().size());
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, ctx.getContextUrls().get(0));
    }
    
    @Test
    void testFromJsonObject() throws JsonLdException {
        JsonObject obj = new JsonObject();
        obj.addProperty("name", "http://schema.org/name");
        obj.addProperty("email", "http://schema.org/email");
        
        JsonLdContext ctx = JsonLdContext.fromJson(obj);
        
        assertEquals(2, ctx.getTermDefinitions().size());
        assertEquals("http://schema.org/name", ctx.getTermDefinitions().get("name"));
        assertEquals("http://schema.org/email", ctx.getTermDefinitions().get("email"));
    }
    
    @Test
    void testFromJsonMixed() throws JsonLdException {
        JsonArray array = new JsonArray();
        array.add(JsonLdContext.W3C_VC_CONTEXT);
        
        JsonObject terms = new JsonObject();
        terms.addProperty("name", "http://schema.org/name");
        array.add(terms);
        
        JsonLdContext ctx = JsonLdContext.fromJson(array);
        
        assertEquals(1, ctx.getContextUrls().size());
        assertEquals(1, ctx.getTermDefinitions().size());
        assertEquals(JsonLdContext.W3C_VC_CONTEXT, ctx.getContextUrls().get(0));
        assertEquals("http://schema.org/name", ctx.getTermDefinitions().get("name"));
    }
    
    @Test
    void testFromJsonNull() {
        assertThrows(JsonLdException.class, () -> {
            JsonLdContext.fromJson(null);
        });
    }
    
    @Test
    void testMerge() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addTermDefinition("name", "http://schema.org/name");
        
        JsonLdContext other = new JsonLdContext();
        other.addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        other.addTermDefinition("email", "http://schema.org/email");
        
        context.merge(other);
        
        assertEquals(2, context.getContextUrls().size());
        assertEquals(2, context.getTermDefinitions().size());
        assertTrue(context.getContextUrls().contains(JsonLdContext.W3C_VC_CONTEXT));
        assertTrue(context.getContextUrls().contains("https://www.w3.org/2018/credentials/examples/v1"));
        assertEquals("http://schema.org/name", context.getTermDefinitions().get("name"));
        assertEquals("http://schema.org/email", context.getTermDefinitions().get("email"));
    }
    
    @Test
    void testMergeNull() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.merge(null);
        
        assertEquals(1, context.getContextUrls().size());
    }
    
    @Test
    void testRoundTripSingleUrl() throws JsonLdException {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        
        JsonElement json = context.toJson();
        JsonLdContext restored = JsonLdContext.fromJson(json);
        
        assertEquals(context, restored);
    }
    
    @Test
    void testRoundTripMultipleUrls() throws JsonLdException {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        
        JsonElement json = context.toJson();
        JsonLdContext restored = JsonLdContext.fromJson(json);
        
        assertEquals(context, restored);
    }
    
    @Test
    void testRoundTripWithTerms() throws JsonLdException {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addTermDefinition("name", "http://schema.org/name");
        context.addTermDefinition("email", "http://schema.org/email");
        
        JsonElement json = context.toJson();
        JsonLdContext restored = JsonLdContext.fromJson(json);
        
        assertEquals(context, restored);
    }
    
    @Test
    void testEquals() {
        JsonLdContext ctx1 = new JsonLdContext();
        ctx1.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        ctx1.addTermDefinition("name", "http://schema.org/name");
        
        JsonLdContext ctx2 = new JsonLdContext();
        ctx2.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        ctx2.addTermDefinition("name", "http://schema.org/name");
        
        assertEquals(ctx1, ctx2);
        assertEquals(ctx1.hashCode(), ctx2.hashCode());
    }
    
    @Test
    void testNotEquals() {
        JsonLdContext ctx1 = new JsonLdContext();
        ctx1.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        
        JsonLdContext ctx2 = new JsonLdContext();
        ctx2.addContextUrl("https://www.w3.org/2018/credentials/examples/v1");
        
        assertNotEquals(ctx1, ctx2);
    }
    
    @Test
    void testToString() {
        context.addContextUrl(JsonLdContext.W3C_VC_CONTEXT);
        context.addTermDefinition("name", "http://schema.org/name");
        
        String str = context.toString();
        assertTrue(str.contains("JsonLdContext"));
        assertTrue(str.contains(JsonLdContext.W3C_VC_CONTEXT));
        assertTrue(str.contains("name"));
    }
    
    @Test
    void testMethodChaining() {
        JsonLdContext ctx = new JsonLdContext()
            .addContextUrl(JsonLdContext.W3C_VC_CONTEXT)
            .addTermDefinition("name", "http://schema.org/name")
            .addTermDefinition("email", "http://schema.org/email");
        
        assertEquals(1, ctx.getContextUrls().size());
        assertEquals(2, ctx.getTermDefinitions().size());
    }
}

// Made with Bob