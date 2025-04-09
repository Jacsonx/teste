package org.example;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        //recebe entrada do usuario
        System.out.println("Digite as letras (ex: {a, b, c})");
        String letras = scanner.nextLine().trim();

        //regex para verificar o formato da entrada "caso contenha numeros, simbolos etc"
        if (!letras.matches("\\{([a-zA-Z]\\s*,\\s*)*[a-zA-Z]\\}")) {
            System.out.println("Formato inválido. Digite apenas letras no formato {a, b, c}");
            return;
        }

        //regex tratando as letras para remover simbolos da entrada e padronizando para minusculo
        String letrasTratadas = letras.replaceAll("[\\{\\},\\s]", "").toLowerCase();


        List<String> anagramas = gerarAnagramas(letrasTratadas);

        //exibe lista de anagramas gerados
        System.out.println("\nAnagramas gerados (" + anagramas.size() + "):");
        for (String s : anagramas) {
            System.out.println(s);
        }
    }

    public static List<String> gerarAnagramas(String entrada) {
        List<String> resultado = new ArrayList<>();
        //funcao recursiva para pegar os anagramas e botar na lista
        gerar("", entrada, resultado);
        return resultado;
    }

    private static void gerar(String combinacao, String letras, List<String> resultado) {
        //se nao tiverem letras sobrando = combinacao terminada, logo adiciona a combinacao a lista de resultados
        if (letras.length() == 0) {
            resultado.add(combinacao);
        } else {
            // realiza o loop enquanto ha letras restantes
            for (int i = 0; i < letras.length(); i++) {
                //adiciona a letra atual na combinacao
                //remove essa letra da lista de letras restantes para a proxima chamada
                //chama a funcao recursivamente com a nova combinacao e as letras restantes
                gerar(
                        combinacao + letras.charAt(i),
                        letras.substring(0, i) + letras.substring(i + 1),
                        resultado
                );
            }
        }
    }
}