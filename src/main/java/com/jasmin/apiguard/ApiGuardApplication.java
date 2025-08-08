package com.jasmin.apiguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
@ConfigurationPropertiesScan
public class ApiGuardApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiGuardApplication.class, args);
	}

}
