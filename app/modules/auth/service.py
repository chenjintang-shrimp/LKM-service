from sqlalchemy.orm import Session

from app.db.models import Profile
from app.db.repo import get_or_raise
from app.modules.auth.errors import AuthErr
from app.modules.auth.schemas import ProfileInfo, ProfileUpdate


def get_profile(db: Session, user_id: int) -> ProfileInfo:
    profile = get_or_raise(db, Profile, AuthErr.USER_NOT_FOUND, Profile.user_id == user_id)
    return ProfileInfo.model_validate(profile)


def update_profile(db: Session, user_id: int, info: ProfileUpdate) -> None:
    profile = get_or_raise(db, Profile, AuthErr.USER_NOT_FOUND, Profile.user_id == user_id)
    if info.nickname is not None:
        profile.nickname = info.nickname
    if info.avatar is not None:
        profile.avatar = info.avatar
    db.flush()
