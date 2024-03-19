package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;


@SpringBootApplication

public class NewOidcOtvApplication extends SpringBootServletInitializer{

	 @Override
     protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
         return application.sources(NewOidcOtvApplication.class);
     }
	 
	public static void main(String[] args) {
		SpringApplication.run(NewOidcOtvApplication.class, args);
	}

}
