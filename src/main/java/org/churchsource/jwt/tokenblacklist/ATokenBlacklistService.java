package org.churchsource.jwt.tokenblacklist;

import org.churchsource.jwt.JwtTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
public abstract class ATokenBlacklistService implements IJwtTokenBlacklistService, ApplicationListener<BlacklistTokenEvent> {

    @Autowired
    private JwtTokenService jwtTokenService;

    @Override
    public void onApplicationEvent(BlacklistTokenEvent blackListTokenEvent) {
        String username = jwtTokenService.getUsernameFromToken(blackListTokenEvent.getToken());
        if(username != null && !"".equals(username)) {
            this.blacklistToken(username, blackListTokenEvent.getToken());
        }
    }
}
