"""Иерархия исключений AI-слоя."""

from __future__ import annotations


class AdminTwinAIError(Exception):
    """Базовое исключение пакета."""


# --- Провайдеры -------------------------------------------------------------


class ProviderError(AdminTwinAIError):
    """Ошибка вызова провайдера LLM."""

    retryable: bool = False

    def __init__(self, message: str, *, provider: str = "", status_code: int | None = None):
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code


class ProviderUnavailableError(ProviderError):
    """Сеть, таймаут, 5xx, перегрузка — переключаемся на следующего кандидата."""

    retryable = True


class ProviderRateLimitedError(ProviderError):
    """Сигнал rate limit (API или подписочный канал, §6.7)."""

    retryable = True

    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        status_code: int | None = 429,
        retry_after_s: float | None = None,
    ):
        super().__init__(message, provider=provider, status_code=status_code)
        self.retry_after_s = retry_after_s


class ProviderRequestError(ProviderError):
    """Неисправимая ошибка запроса (4xx, кроме 408/409/429)."""


class CapabilityNotSupportedError(ProviderError):
    """Провайдер×режим не поддерживает запрошенную возможность."""


class ProviderConfigError(AdminTwinAIError):
    """Некорректная конфигурация провайдера или Model Profile."""


# --- Model Profiles ---------------------------------------------------------


class ProfileSwitchRefusedError(AdminTwinAIError):
    """Новый профиль не покрывает требуемые capabilities агента (§6.3)."""

    def __init__(self, agent_id: str, profile_id: str, missing: list[str]):
        super().__init__(
            f"profile '{profile_id}' does not cover capabilities required by agent "
            f"'{agent_id}': missing {', '.join(missing)}"
        )
        self.agent_id = agent_id
        self.profile_id = profile_id
        self.missing = missing


# --- Контракты --------------------------------------------------------------


class InvalidTransitionError(AdminTwinAIError):
    """Недопустимый переход state machine задачи (§7)."""


class ContractValidationError(AdminTwinAIError):
    """Сообщение не соответствует JSON Schema контракта."""


# --- Агенты -----------------------------------------------------------------


class AgentDefinitionError(AdminTwinAIError):
    """Определение агента нарушает инварианты (§5.2, §23 п.10)."""


# --- Tool Layer --------------------------------------------------------------


class ToolRegistrationError(AdminTwinAIError):
    """Попытка зарегистрировать недопустимый инструмент (например, kind=execute)."""
