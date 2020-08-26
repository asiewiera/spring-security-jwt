package com.ge.springsecurityjwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExampleController {

    @GetMapping("/hello")
    public String hello(Authentication authentication){
        return "Ge my hero";
    }

    @GetMapping("/hello/u")
    public String helloUser(Authentication authentication){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username;
        if (principal instanceof UserDetails) {
            username = ((UserDetails)principal).getUsername();
        } else {
            username = principal.toString();
        }
        return "Hello " + username;
    }

    @GetMapping("/hello/a")
    public String helloAdmin(Authentication authentication){
        return "Ge my hero, admin";
    }

}
