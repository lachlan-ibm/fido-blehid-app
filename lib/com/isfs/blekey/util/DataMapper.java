package com.isfs.blekey.util;

import java.io.ByteArrayInputStream;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;

public class DataMapper {

    private static ObjectMapper om = new ObjectMapper();

    // When 3.0 GAs we should use CBORMapper instead
    private static CBORFactory cf = new CBORFactory();
    // cm does not allow trailing junk, our default desired behavior
    private static ObjectMapper cm = new ObjectMapper(cf);

    public static Map jsonToMap(JsonObject jo) throws Exception {
        return om.readValue(jo.toString().getBytes(), Map.class);
    }

    public static JsonObject objectToJson(Object o) throws Exception {
        return Json.createReader(new ByteArrayInputStream(om.writeValueAsBytes(o))).readObject();
    }

}
