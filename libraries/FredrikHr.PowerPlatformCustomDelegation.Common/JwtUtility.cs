using System.Text.Json;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

public static class JwtUtility
{
    internal static System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler JwtRawHandler { get; } = new();

    public static Entity? GetJwtEntity(string? accessToken)
    {
        if (accessToken is null) return null;
        Entity jwtEntity = new();
        try
        {
            var jwt = JwtRawHandler.ReadJwtToken(accessToken);
            jwtEntity[nameof(jwt.Header)] = JwtDictionaryToEntity(jwt.Header);
            jwtEntity[nameof(jwt.Payload)] = JwtDictionaryToEntity(jwt.Payload);
            jwtEntity["Signature"] = jwt.RawSignature;
        }
        catch (ArgumentException argExcept)
        {
            Entity exceptEntity = new();
            exceptEntity[nameof(Type)] = argExcept.GetType().Name;
            exceptEntity[nameof(argExcept.Message)] = argExcept.Message;
            exceptEntity[nameof(argExcept.HResult)] = argExcept.HResult;
            jwtEntity[nameof(Exception)] = exceptEntity;
        }

        return jwtEntity;
    }

    private static Entity? JwtDictionaryToEntity(Dictionary<string, object?>? jwtDict)
    {
        if (jwtDict is null) return null;
        Entity jwtEntity = new();

        foreach (var jwtClaim in jwtDict)
        {
            object? jwtValue = jwtClaim.Value switch
            {
                JsonElement jsonElement => GetEntityAttributeValue(jsonElement),
                _ => jwtClaim.Value,
            };
            jwtEntity[jwtClaim.Key] = jwtValue;
        }

        return jwtEntity;

        static object? GetEntityAttributeValue(JsonElement jsonElement)
        {
            return jsonElement.ValueKind switch
            {
                JsonValueKind.Null => null,
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.String => jsonElement.GetString(),
                JsonValueKind.Number =>
                    jsonElement.TryGetInt32(out int jsonInt)
                    ? jsonInt
                    : jsonElement.TryGetInt64(out long jsonLong)
                    ? jsonLong
                    : jsonElement.GetDouble(),
                JsonValueKind.Array => GetEntityAttributeValueFromArray(jsonElement),
                JsonValueKind.Object => JwtDictionaryToEntity(jsonElement.Deserialize<Dictionary<string, object?>>()!),
                _ => jsonElement.Deserialize<Dictionary<string, object?>>(),
            };

            static object? GetEntityAttributeValueFromArray(JsonElement jsonElement)
            {
                object?[] jsonArray = new object?[jsonElement.GetArrayLength()];
                int jsonArrayIdx = 0;
                bool allItemsString = true;
                foreach (var jsonArrayElement in jsonElement.EnumerateArray())
                {
                    object? jsonArrayItemValue = GetEntityAttributeValue(jsonArrayElement);
                    jsonArray[jsonArrayIdx] = jsonArrayItemValue;
                    allItemsString &= jsonArrayItemValue is string ||
                        jsonArrayItemValue is null;

                    jsonArrayIdx++;
                }
                return (allItemsString && jsonArray.Length > 0)
                    ? Array.ConvertAll(jsonArray, o => o as string)
                    : jsonArray;
            }
        }
    }
}