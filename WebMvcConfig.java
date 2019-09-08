/**
 * 
 */
package com.exide.sfcrm.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.resource.PathResourceResolver;

import com.exide.sfcrm.constants.PropertyConstants;

/**
 * @author saurabhp
 *
 */
//@Configuration
public class WebMvcConfig  extends WebMvcConfigurerAdapter{
	
	@Autowired
	private PropertyConstants propertyConstants;
	
	
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**").allowedMethods("GET", "POST", "PUT", "DELETE").allowedOrigins("*")
        .allowedHeaders("*");
	} 

	@Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
		
      registry.addResourceHandler(propertyConstants.APP_CONTEXT+"/*")
        .addResourceLocations("classpath:"+propertyConstants.APP_STATIC_PATH)
        .resourceChain(true)
        .addResolver(new PathResourceResolver() {
            @Override
            protected Resource getResource(String resourcePath,
                Resource location) throws IOException {
                Resource requestedResource = location.createRelative(resourcePath);
                return requestedResource.exists() && requestedResource.isReadable() ? requestedResource
                : new ClassPathResource("/static/index.html");
            }
        });
    }
}
