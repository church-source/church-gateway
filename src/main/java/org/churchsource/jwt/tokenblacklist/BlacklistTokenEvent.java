package org.churchsource.jwt.tokenblacklist;

import lombok.*;
import org.springframework.context.ApplicationEvent;

@Getter
@Setter
@ToString
@EqualsAndHashCode(callSuper=false)
public class BlacklistTokenEvent extends ApplicationEvent {
    private String token;

    @Builder(builderMethodName="aBlacklistTokenEvent")
    public BlacklistTokenEvent(Object source, String token) {
        super(source);
        this.token = token;
    }
}
