package org.churchsource.jwt.tokenblacklist;

import org.churchsource.jwt.JwtTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class InMemoryTokenBlacklistService extends ATokenBlacklistService {

    // TODO presently the blacklist cache is in memory as below. This means on server restart the entire blacklist is lost
    // Idea is to move this into Redis in future. For now will drop the token lifetime as well to 15 minutes.
    // This will also not work if another instance of this service is created (for whatever reason, e.g. scaling)
    private static Map<String, Set<String>> blacklistTokenCache = new HashMap<String, Set<String>>();

    @Autowired
    private JwtTokenService jwtTokenService;

    protected Map<String, Set<String>> getBlacklistTokenCache() {
        return blacklistTokenCache;
    }

    @Override
    public Boolean isTokenBlacklisted(String userName, String token) {
        Set<String> tokenSet = getBlacklistTokenCache().get(userName);
        if(tokenSet != null && tokenSet.contains(token))
            return true;
        return false;
    }

    @Override
    public void blacklistToken(String userName, String token) {
        Set<String> tokenSet = getBlacklistTokenCache().get(userName);
        if(tokenSet == null) {
            tokenSet = new HashSet<String>();
            getBlacklistTokenCache().put(userName, tokenSet);
        }
        tokenSet.add(token);
        removeExpiredTokens(tokenSet);
    }

    /**
     * Remove expired tokens from cache in a lazy fashion
     * @param tokenSet
     */
    protected void removeExpiredTokens(Set<String> tokenSet) {
        new Thread(() -> {
            for (Iterator<String> i = tokenSet.iterator(); i.hasNext();) {
                String t = i.next();
                if (jwtTokenService.isTokenExpired(t)) {
                    i.remove();
                }
            }
        }).start();
    }
}
