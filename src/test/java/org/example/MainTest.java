package org.example;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

public class MainTest {
    @Test
    public void testAnagramasNormais() {
        List<String> resultado = Main.gerarAnagramas("abc");
        assertEquals(6, resultado.size());
        assertTrue(resultado.contains("abc"));
        assertTrue(resultado.contains("cba"));
    }

    @Test
    public void testUmaLetra() {
        List<String> resultado = Main.gerarAnagramas("a");
        assertEquals(1, resultado.size());
        assertEquals("a", resultado.get(0));
    }

    @Test
    public void testEntradaVazia() {
        List<String> resultado = Main.gerarAnagramas("");
        assertEquals(1, resultado.size());  // Retorna uma string vazia como resultado
        assertEquals("", resultado.get(0));
    }

    @Test
    public void testComEspacosTratados() {
        String entradaTratada = "{ a, b , c }".replaceAll("[\\{\\},\\s]", "").toLowerCase();
        List<String> resultado = Main.gerarAnagramas(entradaTratada);
        assertEquals(6, resultado.size());
    }

    @Test
    public void testLetrasRepetidas() {
        List<String> resultado = Main.gerarAnagramas("aab");
        assertEquals(6, resultado.size()); // Pode gerar duplicados
        assertTrue(resultado.contains("aab"));
        assertTrue(resultado.contains("aba"));
    }

}
