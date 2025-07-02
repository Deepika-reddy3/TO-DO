from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    mongodb_uri: str
    jwt_secret_key: str
    access_token_expire_minutes: int = 60

    class Config:
        env_file = ".env"
        