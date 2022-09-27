package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{
	
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		 
    	  auth.inMemoryAuthentication()
    	      .withUser("Naveen")
    	      .password("Naveen")
    	      .roles("User")
    	      .and()
    	      .withUser("Kumar")
    	      .password("Kumar")
    	      .roles("Admin");	  
	}
     @Bean
      public PasswordEncoder getPasswordEncoder() {
    	  return NoOpPasswordEncoder.getInstance();
      }
      

  	/*protected void configure(HttpSecurity http) throws Exception {
  		 http.authorizeRequests()
  		     .antMatchers("/admin").hasRole("Admin")
  		     .antMatchers("/user").hasRole("User")
  		     //.antMatchers("/").permitAll()
  		     .and().formLogin();
  	}*/
}
