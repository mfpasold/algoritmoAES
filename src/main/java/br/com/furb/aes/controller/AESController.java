package br.com.furb.aes.controller;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import br.com.furb.aes.service.AESService;

@RestController
public class AESController {

	@Autowired
	AESService service;
	
	@RequestMapping(method = RequestMethod.POST, value="/criptografar", consumes = "multipart/form-data")
	@ResponseBody
	public String criptografar(@RequestPart("file") MultipartFile file, @RequestParam String key, @RequestParam String fileName) throws UnsupportedEncodingException, IOException {
		String contentFile = new String(file.getBytes(), "ASCII");
		byte[] result = service.cifrar(contentFile, key);
		service.saveFile(fileName, result);
		return new String(result);
	}
}
