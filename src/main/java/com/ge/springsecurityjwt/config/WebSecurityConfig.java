package com.ge.springsecurityjwt.config;


import com.ge.springsecurityjwt.filter.JwtFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {



    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/hello/a").hasAuthority("ROLE_ADMIN")
                .antMatchers("/hello/u").hasAnyRole("ADMIN", "USER")
                .anyRequest().permitAll()
                .and().addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class);
    }


}
