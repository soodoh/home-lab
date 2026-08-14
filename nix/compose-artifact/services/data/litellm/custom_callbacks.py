from litellm.integrations.custom_logger import CustomLogger


class ServiceTierPassthrough(CustomLogger):
    async def async_pre_call_hook(
        self,
        user_api_key_dict,
        cache,
        data,
        call_type,
    ):
        model = data.get("model")
        if (
            call_type == "aresponses"
            and isinstance(model, str)
            and model.startswith("chatgpt/")
            and data.get("service_tier") == "priority"
        ):
            extra_body = data.setdefault("extra_body", {})
            if isinstance(extra_body, dict):
                extra_body["service_tier"] = data.pop("service_tier")

        return data


service_tier_passthrough = ServiceTierPassthrough()
