package org.churchsource.jwt.tokenblacklist;

public interface IJwtTokenBlacklistService {
    public Boolean isTokenBlacklisted(String userName, String token);

    public void blacklistToken(String userName, String token);
}
