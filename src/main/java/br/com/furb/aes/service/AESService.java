package br.com.furb.aes.service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import br.com.furb.aes.utils.SBox;
import br.com.furb.aes.utils.TabelaE;
import br.com.furb.aes.utils.TabelaL;

@Service
public class AESService {

	private static ArrayList<ArrayList<Integer>> roundKeys;
	private static Integer[] roundConstants = new Integer[]{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
	
	public String descriptografar(byte[] byteText) {
		try {

			byte[] chave = new byte[] {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P'};
			SecretKeySpec chaveSecreta = new SecretKeySpec(chave, "AES");

			Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");

			cifra.init(Cipher.DECRYPT_MODE, chaveSecreta);

			byte[] descriptografado = cifra.doFinal(byteText);
			
			return new String(descriptografado);
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}

	}
	
	public void saveFile(String fileName, byte[] cipherText) {
		String pathName = "C:\\Temp\\%s.bin";
		try (FileWriter fileWriter = new FileWriter(new File(String.format(pathName, fileName)));
				PrintWriter printWriter = new PrintWriter(fileWriter);) {
			printWriter.print(cipherText);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public byte[] cifrar(String texto, String chave) {
		
		roundKeys = new ArrayList<ArrayList<Integer>>(44);
		
		expandirChave(chave);
		byte[] textoCifrado = cifragemEmBloco(texto);
		
		return textoCifrado;
		
	}
	
	private void carregarKeySchedule() {
		for(int i = 4; i < 44; i += 4) {
			roundKeys.add(carregarPrimeiraRoundKey(i));
			roundKeys.add(xor(roundKeys.get(i-3), roundKeys.get(i)));
			roundKeys.add(xor(roundKeys.get(i-2), roundKeys.get(i+1)));
			roundKeys.add(xor(roundKeys.get(i-1), roundKeys.get(i+2)));
			printRoundKey(roundKeys, i);
		}
		
	}

	private ArrayList<Integer> xor(ArrayList<Integer> roundKey1, ArrayList<Integer> roundKey2) {
		ArrayList<Integer> newArray = new ArrayList<Integer>();
		for (int i = 0; i < 4; i++) {
			newArray.add(roundKey1.get(i) ^ roundKey2.get(i));
		}
		return newArray;
		
	}

	private ArrayList<Integer> carregarPrimeiraRoundKey(int i) {
		ArrayList<Integer> lastRoundKey = new ArrayList<Integer>(roundKeys.get(i-1));
		
		//RotWord
		Collections.rotate(lastRoundKey, 3);
		
		//SubWord
		lastRoundKey = (ArrayList<Integer>)SBox.substituicao(lastRoundKey);
		
		//RoundConstant
		ArrayList<Integer> roundConstant = getRoundConstant(i);
		
		lastRoundKey = xor(lastRoundKey, roundConstant);
		
		//Obter primeira palavra
		lastRoundKey = xor(lastRoundKey, roundKeys.get(i-4));
		
		return lastRoundKey;
		
	}

	private ArrayList<Integer> getRoundConstant(int i) {
		ArrayList<Integer> roundConstant = new ArrayList<Integer>();
		roundConstant.add(roundConstants[(i/4)-1]);
		roundConstant.add(0);
		roundConstant.add(0);
		roundConstant.add(0);
		return roundConstant;
	}

	private void expandirChave(String chave) {
		String[] bytesChave = chave.split(",");
		dividirChaveEmBlocos(bytesChave);
		
		printRoundKey(roundKeys, 0);
		
		carregarKeySchedule();
		
	}
	
	private void dividirChaveEmBlocos(String[] bytesChave) {
		ArrayList<Integer> palavra = new ArrayList<Integer>(4);
		
		for(int i = 0; i < bytesChave.length; i++) {
			palavra.add(Integer.parseInt(bytesChave[i]));
			
			if ((i + 1) % 4 == 0) {
				roundKeys.add(palavra);
				palavra = new ArrayList<Integer>(4);
			}
		}
		return;
	}

	private byte[] cifragemEmBloco(String texto) {
		List<String> blocos = dividirTextoEmBlocos(texto);
		StringBuilder textoCifrado = new StringBuilder(); 
		byte[] retorno = new byte[blocos.size()*16];
		int tamanho = 0;
		for (String bloco : blocos) {
			ArrayList<ArrayList<Integer>> matriz = new ArrayList<ArrayList<Integer>>();
			int index = 0;
			for(int i = 0; i < 4; i++) {
				ArrayList<Integer> palavra = new ArrayList<Integer>();
				for(int j = 0; j < 4; j++) {
					palavra.add((int) bloco.charAt(index++));
				}
				matriz.add(palavra);
			}
			
			printTable("Texto simples", matriz);
			
			ArrayList<ArrayList<Integer>> novaMatriz = new ArrayList<ArrayList<Integer>>();
			novaMatriz.add(xor(matriz.get(0), roundKeys.get(0)));
			novaMatriz.add(xor(matriz.get(1), roundKeys.get(1)));
			novaMatriz.add(xor(matriz.get(2), roundKeys.get(2)));
			novaMatriz.add(xor(matriz.get(3), roundKeys.get(3)));
			
			matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
			novaMatriz.clear();
			printTable("RoundKey 0", matriz);
			
			for(int k = 0; k < 9; k++) {
				subBytes(matriz, novaMatriz);
				
				matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
				novaMatriz.clear();
				printTable("SubBytes-Round "+(k+1),matriz);
				
				shiftRows(matriz, novaMatriz);
				
				matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
				novaMatriz.clear();
				printTable("ShiftRows-Round "+(k+1),matriz);
				
				mixColumns(matriz, novaMatriz);
				
				matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
				novaMatriz.clear();
				printTable("MixedColumns-Round "+(k+1),matriz);
				
				addRoundKey(matriz, novaMatriz, k);
				
				matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
				novaMatriz.clear();
				printTable("addRoundKey-Round "+(k+1),matriz);	
			}
			
			subBytes(matriz, novaMatriz);
			
			matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
			novaMatriz.clear();
			printTable("SubBytes-Round 10", matriz);
			
			shiftRows(matriz, novaMatriz);
			
			matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
			novaMatriz.clear();
			printTable("ShiftRows-Round 10", matriz);
			
			addRoundKey(matriz, novaMatriz, 9);
			
			matriz = new ArrayList<ArrayList<Integer>>(novaMatriz);
			novaMatriz.clear();
			printTable("addRoundKey-Round 10", matriz);
			
			tamanho = loadBytesByMatriz(matriz, retorno, tamanho);
			
		}
		
		return retorno;
		
	}
	
	private int loadBytesByMatriz(ArrayList<ArrayList<Integer>> matriz, byte[] bytes, int tamanho) {
		int count = tamanho;
		for(int i = 0; i < matriz.size(); i++) {
			for(int j = 0; j < matriz.get(i).size(); j++) {
				bytes[count] = matriz.get(i).get(j).byteValue();
				count++;
			}
		}

		return count;
	}

	private String getTextByMatriz(ArrayList<ArrayList<Integer>> matriz) {
		StringBuilder str = new StringBuilder();
		for(int i = 0; i < matriz.size(); i++) {
			for(int j = 0; j < matriz.get(i).size(); j++) {
				str.append(toHex(matriz.get(i).get(j), false));
			}
		}

		return str.toString();
	}

	private void shiftRows(ArrayList<ArrayList<Integer>> matriz, ArrayList<ArrayList<Integer>> novaMatriz) {
		novaMatriz.add(new ArrayList<Integer>(Arrays.asList(matriz.get(0).get(0), 
				matriz.get(1).get(1), 
				matriz.get(2).get(2), 
				matriz.get(3).get(3) )));
		novaMatriz.add(new ArrayList<Integer>(Arrays.asList(matriz.get(1).get(0), 
				matriz.get(2).get(1), 
				matriz.get(3).get(2), 
				matriz.get(0).get(3) )));
		novaMatriz.add(new ArrayList<Integer>(Arrays.asList(matriz.get(2).get(0), 
				matriz.get(3).get(1), 
				matriz.get(0).get(2), 
				matriz.get(1).get(3) )));
		novaMatriz.add(new ArrayList<Integer>(Arrays.asList(matriz.get(3).get(0), 
				matriz.get(0).get(1), 
				matriz.get(1).get(2), 
				matriz.get(2).get(3) )));
	}

	private void subBytes(ArrayList<ArrayList<Integer>> matriz, ArrayList<ArrayList<Integer>> novaMatriz) {
		novaMatriz.add((ArrayList<Integer>)SBox.substituicao(matriz.get(0)));
		novaMatriz.add((ArrayList<Integer>)SBox.substituicao(matriz.get(1)));
		novaMatriz.add((ArrayList<Integer>)SBox.substituicao(matriz.get(2)));
		novaMatriz.add((ArrayList<Integer>)SBox.substituicao(matriz.get(3)));
	}
	
	private void addRoundKey(ArrayList<ArrayList<Integer>> matriz, ArrayList<ArrayList<Integer>> novaMatriz,
			int k) {
		int posicaoRoundKey = (k+1)*4;
		novaMatriz.add(xor(matriz.get(0), roundKeys.get(posicaoRoundKey)));
		novaMatriz.add(xor(matriz.get(1), roundKeys.get(posicaoRoundKey+1)));
		novaMatriz.add(xor(matriz.get(2), roundKeys.get(posicaoRoundKey+2)));
		novaMatriz.add(xor(matriz.get(3), roundKeys.get(posicaoRoundKey+3)));		
	}

	private void mixColumns(ArrayList<ArrayList<Integer>> matriz,
			ArrayList<ArrayList<Integer>> novaMatriz) {
		for(int i = 0; i < matriz.size(); i++) {
			ArrayList<Integer> palavra = new ArrayList<Integer>();
			palavra.add(galois(matriz.get(i).get(0), 2) ^ galois(matriz.get(i).get(1), 3) ^ galois(matriz.get(i).get(2), 1) ^ galois(matriz.get(i).get(3), 1));
			palavra.add(galois(matriz.get(i).get(0), 1) ^ galois(matriz.get(i).get(1), 2) ^ galois(matriz.get(i).get(2), 3) ^ galois(matriz.get(i).get(3), 1));
			palavra.add(galois(matriz.get(i).get(0), 1) ^ galois(matriz.get(i).get(1), 1) ^ galois(matriz.get(i).get(2), 2) ^ galois(matriz.get(i).get(3), 3));
			palavra.add(galois(matriz.get(i).get(0), 3) ^ galois(matriz.get(i).get(1), 1) ^ galois(matriz.get(i).get(2), 1) ^ galois(matriz.get(i).get(3), 2));
			novaMatriz.add(palavra);
		}
		return;
	}

	private int galois(Integer fatorMatriz, int fatorConstante) {
		if (fatorMatriz == 0 || fatorConstante == 0) {
			return 0;
		}
		
		if (fatorMatriz == 1) {
			return fatorConstante;
		}
		
		if (fatorConstante == 1) {
			return fatorMatriz;
		}
		
		int fatorL1 = TabelaL.substituicao(fatorMatriz);
		int fatorL2 = TabelaL.substituicao(fatorConstante);
		int soma = fatorL1 + fatorL2;
		
		if (soma > 255) {
			soma = soma - 255;
		}
		return TabelaE.substituicao(soma);
	}

	private List<String> dividirTextoEmBlocos(String texto) {
		List<String> blocos = new ArrayList<String>();
		String aux = texto;
		while(aux.length() > 16) {
			blocos.add(aux.substring(0, 16));
			aux = aux.substring(16);
		}
		
		aux = aux.substring(0, aux.length());
		blocos.add(padding(aux));
		
		if (texto.length() % 4 == 0) {
			blocos.add(padding(""));
		}

		return blocos;
	}

	private String padding(String aux) {
		int paddingValue = 16 - aux.length();
		String newPadding = aux;
		for(int i = 0; i < paddingValue; i++) {
			newPadding += (char)paddingValue;
		}
		
		return newPadding;
		
	}

	private void printTable(String action, ArrayList<ArrayList<Integer>> roundKeys2) {
		System.out.println("\n" + action);
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < roundKeys2.size(); j++) {
				System.out.print(toHex(roundKeys2.get(j).get(i), true));
				System.out.print(' ');
			}
			System.out.println();
		}
	}
	
	private void printRoundKey(ArrayList<ArrayList<Integer>> roundKeys2, int index) {
		System.out.println("RoundKey " + (index / 4));
		for(int i = 0; i < 4; i++) {
			for(int j = index; j < index+4; j++) {
				System.out.print(toHex(roundKeys2.get(j).get(i), true));
				System.out.print(' ');
			}
			System.out.println();
		}
		System.out.println();
	}
	
	public String toHex(Integer arg, boolean addPrefix) {
		String prefixo = addPrefix ? "0x" : "";
		if (arg <= 15) {
			return String.format(prefixo + "%s", "0" + Integer.toHexString(arg));
		} else {
			return String.format(prefixo + "%s", Integer.toHexString(arg));
		}
	}
}
