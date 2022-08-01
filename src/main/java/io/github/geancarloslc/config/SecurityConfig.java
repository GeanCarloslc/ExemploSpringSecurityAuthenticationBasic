package io.github.geancarloslc.config;

import io.github.geancarloslc.service.impl.UsuarioServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final String USER = "USER";
    private final String ADMIN = "ADMIN";

    @Autowired
    private UsuarioServiceImpl usuarioService;


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    //Responsável pelos objetos que fazem a autenticação, verificando a senha, onde buscar usuarios dentre outros
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.
                userDetailsService(usuarioService)
                .passwordEncoder(passwordEncoder());
    }

    @Override
    //Responsável por utilizar o usuário que foi autenticado no metodo acima e verificar se tem autorização
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                    .authorizeRequests()
                        .antMatchers("/api/clientes/**").hasAnyRole(USER, ADMIN)
                        .antMatchers("/api/produtos/**").hasAnyRole(ADMIN)
                        .antMatchers("/api/pedidos/**").hasAnyRole(USER, ADMIN)
                        .antMatchers("/api/usuarios/**").hasAnyRole(ADMIN)
                .anyRequest().authenticated()
                .and() //Retorna para a raiz do objeto (http)
                    .httpBasic();
    }
}
