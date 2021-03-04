package org.churchsource.filters;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.churchsource.jwt.JwtTokenService;
import org.churchsource.jwt.tokenblacklist.IJwtTokenBlacklistService;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.http.HttpStatus;


@Slf4j
@Component
public class AuthPreFilter extends AbstractGatewayFilterFactory<AuthPreFilter.Config> {

	public AuthPreFilter() {
		super(Config.class);
	}


	@Autowired
	private JwtTokenService jwtTokenService;

	@Autowired
	private IJwtTokenBlacklistService blacklistService;

	@Value("${jwt.http.request.header}")
	private String tokenHeader;

	@Override
	public GatewayFilter apply(Config config) {
		System.out.println("inside AuthPreFilter.apply method");
		
		return (exchange, chain) -> {

			ServerHttpRequest request = exchange.getRequest().mutate().header("scgw-pre-header", Math.random()*10+"").build();

			String jwtToken = "";
			String username = "";
			final String requestTokenHeader = exchange.getRequest().getHeaders().getFirst(this.tokenHeader);
			if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
				jwtToken = requestTokenHeader.substring(7);
				try {
					username = jwtTokenService.getUsernameFromToken(jwtToken);
				} catch (IllegalArgumentException e) {
					log.error("JWT_TOKEN_UNABLE_TO_GET_USERNAME", e);
				} catch (ExpiredJwtException e) {
					log.warn("JWT_TOKEN_EXPIRED", e);
				}
			} else {
				log.warn("JWT_TOKEN_DOES_NOT_START_WITH_BEARER_STRING");
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}
			log.debug("JWT_TOKEN_USERNAME_VALUE '{}'", username);
			if (username != null && !blacklistService.isTokenBlacklisted(username, jwtToken)) {
				try {
					if (!jwtTokenService.validateToken(jwtToken)) {
						exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
						return exchange.getResponse().setComplete();
					}
				} catch (Exception e) {
					exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					return exchange.getResponse().setComplete();
				}
			} else {
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}
			return chain.filter(exchange.mutate().request(request).build());
		};
	}

	public static class Config {
		private String name;
		
		public String getName() {
			return this.name;
		}
		
		public void setName(String name) {
			this.name = name;
		}
	}
}
