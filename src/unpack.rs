use crate::errors::{UnpackError, UnpackResult};

use serde_json::{Map, Number, Value};

pub type JsonObject = Map<String, Value>;
pub type JsonArray = Vec<Value>;

pub fn as_object(val: &Value) -> UnpackResult<&JsonObject> {
    match val {
        Value::Object(obj) => Ok(obj),
        _ => Err(UnpackError::unmarshal("object")),
    }
}

pub fn as_array(val: &Value) -> UnpackResult<&JsonArray> {
    match val {
        Value::Array(arr) => Ok(arr),
        _ => Err(UnpackError::unmarshal("array")),
    }
}

pub fn as_string(val: &Value) -> UnpackResult<&String> {
    match val {
        Value::String(string) => Ok(string),
        _ => Err(UnpackError::unmarshal("string")),
    }
}

pub fn as_number(val: &Value) -> UnpackResult<&Number> {
    match val {
        Value::Number(num) => Ok(num),
        _ => Err(UnpackError::unmarshal("number")),
    }
}

pub fn get_key<'a>(obj: &'a JsonObject, key: &str) -> UnpackResult<&'a Value> {
    match obj.get(key) {
        Some(val) => Ok(val),
        _ => Err(UnpackError::missing_key(key)),
    }
}

pub fn as_object_get_key<'a>(val: &'a Value, key: &str) -> UnpackResult<&'a Value> {
    Ok(get_key(as_object(val)?, key)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_OBJECT: &str = "{\"foo\": \"bar\"}";
    const JSON_ARRAY: &str = "[\"foo\", \"bar\"]";
    const JSON_STRING: &str = "\"foobar\"";
    const JSON_NUMBER: &str = "123";

    fn to_value(payload: &str) -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(payload).unwrap()
    }

    #[test]
    fn test_as_object() {
        let obj = to_value(JSON_OBJECT);
        let result = as_object(&obj);

        assert!(result.is_ok());
        assert_eq!(
            as_string(get_key(result.unwrap(), "foo").unwrap()).unwrap(),
            "bar"
        );
    }

    #[test]
    fn test_as_array() {
        let arr = to_value(JSON_ARRAY);
        let result = as_array(&arr);

        assert!(result.is_ok());

        let items = result.unwrap();

        assert_eq!(items.len(), 2);
        assert_eq!(as_string(&items[0]).unwrap(), "foo");
        assert_eq!(as_string(&items[1]).unwrap(), "bar");
    }

    #[test]
    fn test_as_string() {
        let string = to_value(JSON_STRING);
        let result = as_string(&string);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "foobar");
    }

    #[test]
    fn test_as_number() {
        let number = to_value(JSON_NUMBER);
        let result = as_number(&number);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_u64(), Some(123));
    }

    #[test]
    fn test_as_object_get_key() {
        let obj = to_value(JSON_OBJECT);
        assert_eq!(
            as_string(as_object_get_key(&obj, "foo").unwrap()).unwrap(),
            "bar"
        );
    }
}
