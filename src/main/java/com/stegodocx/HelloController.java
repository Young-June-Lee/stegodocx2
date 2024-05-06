package com.stegodocx;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.control.TextField;

import java.io.*;
import java.util.zip.*;
import java.nio.ByteBuffer;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HelloController {

    @FXML
    private TextField docxTextField;
    @FXML
    private TextField jpegTextField;

    @FXML
    private TextField keyTextField;

    @FXML
    private TextField docxTextResult;

    @FXML
    private TextField jpegResultTextField;

    private Stage docxStage;

    private Stage jpgStage;

    private static final int docxBase64LenBuffer = 128;

    private static final int signatureFF_JPG1 = 0xFF;
    private static final int signatureD9_JPG2 = 0xD9;

    private static final int signature49_PNG1 = 0x49;
    private static final int signature45_PNG2 = 0x45;
    private static final int signature4E_PNG3 = 0x4E;
    private static final int signature44_PNG4 = 0x44;
    private static final int signatureAE_PNG5 = 0xAE;
    private static final int signature42_PNG6 = 0x42;
    private static final int signature60_PNG7 = 0x60;
    private static final int signature82_PNG8 = 0x82;


    private static final String AES_ALGORITHM = "AES";
    private static final String AES_CIPHER_MODE = "AES/CBC/PKCS5Padding";
    private static final String INIT_VECTOR = "0123456789abcdef"; // 16 bytes

    private String secretKey = "1234512345123456"; // 16, 24, or 32 bytes
    private String fileExt = "";

    private void setSecretKey(String str) {
        this.secretKey = str;
    }
    private byte[] getSecretKey() throws UnsupportedEncodingException {
        return this.secretKey.getBytes("UTF-8");
    }

    private void setFileExt(String str) {

        this.fileExt = str;
    }
    private String getFileExt() {
        return this.fileExt;
    }


    @FXML
    protected void selOpenDocxFile() {
        FileChooser fileChooser = new FileChooser();

        fileChooser.getExtensionFilters().addAll((new FileChooser.ExtensionFilter("문서파일 : Docx 파일", "*.docx")));
        File file = fileChooser.showOpenDialog(docxStage);

        if (file != null) {
            docxTextField.setText(file.getPath());
        } else {
            docxTextField.setText("Select Button Click~");
        }

    }


    @FXML
    protected void selOpenJpgFile() {
        FileChooser fileChooser = new FileChooser();

        fileChooser.getExtensionFilters().addAll((new FileChooser.ExtensionFilter("Image 파일", "*.jpg", ".png", ".bmp")));
        File file = fileChooser.showOpenDialog(jpgStage);

        if (file != null) {
            jpegTextField.setText(file.getPath());
        } else {
            jpegTextField.setText("Select Button Click~");
        }
    }




    public String getFileNameWithoutExtension(String fileName) {
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex != -1 && dotIndex > 0) {
            return fileName.substring(0, dotIndex);
        }
        return fileName;
    }

    //파일의 확장자를 리턴
    public String getFileExtension(String fileName) {
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex != -1 && dotIndex < fileName.length() - 1) {
            return fileName.substring(dotIndex + 1);
        }
        return "";
    }

    //결과파일 export 파일명
    private String getResultFile(String jpegTxt) {
        String jpgFileResult = getFileNameWithoutExtension(jpegTxt) +"_result." + getFileExtension(jpegTxt);
        return jpgFileResult;
    }

    // 문자열을 AES로 암호화하는 메서드
    public String encryptAES(byte[] data) {
        try {
            byte[] keyBytes = this.getSecretKey();

            byte[] ivBytes = INIT_VECTOR.getBytes("UTF-8");
            System.out.println("====");
            System.out.println(keyBytes.length);
            System.out.println("====");

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, AES_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(AES_CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            //1. 암호화
            byte[] encryptedBytes = cipher.doFinal(data);

            //2. base64 encode 처리
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // 문자열을 AES로 복호화하는 메서드
    public byte[] decryptAES(byte[] data) {
        try {
            byte[] keyBytes = this.getSecretKey();
            byte[] ivBytes = INIT_VECTOR.getBytes("UTF-8");
            System.out.println("====");
            System.out.println(keyBytes.length);
            System.out.println("====");

            SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, AES_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance(AES_CIPHER_MODE);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            //2. 암호화 할때 base64 encode 처리했으니 다시 decode 처리해아함.
            byte[] base64DecodeData = Base64.getDecoder().decode(data);

            //1. base64디코드 처리된 값을 복호화 처리
            byte[] decryptedBytes = cipher.doFinal(base64DecodeData);

            return  decryptedBytes;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    //특정 주소부터 읽기
    public byte[] readBytesFromOffset(String filePath, int startOffset, int length) {
        byte[] data = new byte[length];

        try (FileInputStream fis = new FileInputStream(filePath)) {
            fis.skip(startOffset); // 지정된 offset 주소로 이동

            int bytesRead = fis.read(data, 0, length);
            if (bytesRead != length) {
                throw new IOException("Failed to read " + length + " bytes from offset " + startOffset);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return data;
    }

    public byte[] intToBytesUsingByteBuffer(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(docxBase64LenBuffer); // 1024바이트 할당
        buffer.putInt(value);

        return buffer.array();
    }
    // 스트림을 String으로
    public StringBuilder convertStreamToString(InputStream inputStream) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        int character;

        while ((character = inputStream.read()) != -1) {
            stringBuilder.append((char) character);
        }

        return stringBuilder;
    }

    public byte[] filetoByteArray(String path) {
        byte[] data;
        try {
            InputStream input = new FileInputStream(path);
            int byteReads;
            ByteArrayOutputStream output = new ByteArrayOutputStream(1024);
            while ((byteReads = input.read()) != -1) {
                output.write(byteReads);
            }
            data = output.toByteArray();
            output.close();
            input.close();
            return data;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * Method to get byte array data from given InputStream
     *
     * @param is InputStream to read
     * @return Stream data as byte array
     */
    public byte[] streamToBytes(InputStream is) throws IOException {
        final int BUF_SIZE = 512;
        int bytesRead;
        byte[] data;

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            data = new byte[BUF_SIZE];

            while ((bytesRead = is.read(data, 0, BUF_SIZE)) >= 0) {
                bos.write(data, 0, bytesRead);
            }

            return bos.toByteArray();
        }
    }

    //docx 를 zip 으로 압축한다.
    public byte[] compressDocxToZip(String docxFilePath) throws IOException {
        byte[] msg = this.filetoByteArray(docxFilePath);
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             GZIPOutputStream zos = new GZIPOutputStream(bos)) {
            zos.write(msg);
            zos.finish();
            zos.flush();
            return bos.toByteArray();
        }
    }

    public String bytesToHex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes) {
            stringBuilder.append(String.format("%02X", b));
        }
        return stringBuilder.toString();
    }

    public String identifyImageFormat(byte[] headerBytes) {
        String headerHex = bytesToHex(headerBytes);

        if (headerHex.startsWith("89504E47")) {
            return "PNG";
        } else if (headerHex.startsWith("424D")) {
            return "BMP";
        } else if (headerHex.startsWith("47494638")) {
            return "GIF";
        } else if (headerHex.startsWith("FFD8FF")) {
            return "JPEG";
        } else {
            return "Unknown";
        }
    }

    //zip 으로 압축된 docx 를 다시 복구한다.
    public byte[] decompressZipToDocx(byte[] msg) throws IOException {
        //byte[] msg = this.filetoByteArray(zipFilePath);
        try (ByteArrayInputStream bis = new ByteArrayInputStream(msg);
             GZIPInputStream zis = new GZIPInputStream(bis)) {
            msg = this.streamToBytes(zis);
        }

        return msg;
    }

    @FXML
    protected void btnFind() throws IOException {
        String jpegTxt = jpegResultTextField.getText();
        String docxTxt = docxTextField.getText();
        String encryptionKey = keyTextField.getText();
        //jpegTxt = "C:\\Users\\websw\\OneDrive\\사진\\pian-grande_result.jpg";
        //docxTxt = "C:\\Users\\websw\\OneDrive\\문서\\안티포렌식 과제 1-파일시그니처_recovery.docx";

        if ("".equals(jpegTxt)|| jpegTxt.isEmpty()) {
            Alert alert = new Alert((Alert.AlertType.INFORMATION));
            alert.setTitle("Information");
            alert.setContentText("JPEG 이미지 파일를 선택해 주세요");
            alert.show();
        } else {

            System.out.println("encryptionKey : "+ encryptionKey);
            if (("".equals(encryptionKey)|| encryptionKey == null|| encryptionKey.isEmpty() )&& encryptionKey.length() != 16) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("Information");
                alert.setContentText("암호는 16자리를 입력해야 합니다");
                alert.show();
            } else {
                //암호 셋팅
                this.setSecretKey(encryptionKey);

                // JPEG 파일을 읽기 위한 FileInputStream 생성
                //FileInputStream fileInputStream = new FileInputStream(jpegTxt);
                //byte[] jpegData = fileInputStream.readAllBytes();

                File file = new File(jpegTxt);
                byte[] jpegData = new byte[(int) file.length()];
                FileInputStream fis = new FileInputStream(file);
                fis.read(jpegData);
                fis.close();

                int ffd9Pos = this.findSignatureIndex(jpegData);

                int docxBase64LenStart = ffd9Pos - docxBase64LenBuffer;
                byte[] docxBas64LenByte = readBytesFromOffset(jpegTxt, docxBase64LenStart, docxBase64LenBuffer);

                //base64로 변환된 docx 파일 길이 읽기
                ByteBuffer buffer = ByteBuffer.wrap(docxBas64LenByte);
                int docxBas64Len = buffer.getInt();
                System.out.println("===docxBas64Len=== : "+ docxBas64Len);

                //docxBase64 스트림 읽기
                //read 시작위치 가져오기(파일 길이 만큼)
                int docxStartLen = docxBase64LenStart - docxBas64Len;
                byte[] docxByte = readBytesFromOffset(jpegTxt, docxStartLen, docxBas64Len);

                //2. AES로 복호화
                byte[] decryptedContent = decryptAES(docxByte);

                //1. zip 압축 해제하고 파일로 저장한다
                byte[] decomPressDocx = decompressZipToDocx(decryptedContent);

                // 수정된 데이터로 DOCX 파일을 생성
                String docxFileResult = getResultFile(docxTxt);
                FileOutputStream fileOutputStream = new FileOutputStream(docxFileResult);
                fileOutputStream.write(decomPressDocx);
                // 스트림 닫기
                fileOutputStream.close();

                docxTextResult.setText(docxFileResult + ",  성공적으로 실행 했습니다.");
                System.out.println("docx writed successfully.");
            }
        }
    }


    @FXML
    protected void btnHidden() throws IOException {
        String docxTxt = docxTextField.getText();
        String jpegTxt = jpegTextField.getText();

        keyTextField.setText("1234567890123456");
        String encryptionKey = keyTextField.getText();
        //docxTxt = "C:\\Users\\websw\\OneDrive\\문서\\안티포렌식 과제 1-파일시그니처.docx";
        //jpegTxt = "C:\\Users\\websw\\OneDrive\\사진\\pian-grande.jpg";

        if ("".equals(docxTxt) || docxTxt.isEmpty()) {
            Alert alert = new Alert((Alert.AlertType.INFORMATION));
            alert.setTitle("ERROR");
            alert.setContentText("은닉할 Docx 문서를 선택해 주세요");
            alert.show();
        } else {
            if ("".equals(jpegTxt)|| jpegTxt == null || jpegTxt.isEmpty()) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("ERROR");
                alert.setContentText("JPEG, PNG, GIF, BMP 파일을 선택해야 합니다");
                alert.show();
            }
            System.out.println("encryptionKey {}"+ encryptionKey);

            if ("".equals(encryptionKey) || encryptionKey == null || encryptionKey.isEmpty()) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("ERROR");
                alert.setContentText("암호는 16자리를 입력해야 합니다");
                alert.show();
            }

            if (encryptionKey.length() != 16) {
                Alert alert = new Alert((Alert.AlertType.INFORMATION));
                alert.setTitle("ERROR");
                alert.setContentText("암호는 16자리를 입력해야 합니다");
                alert.show();
            } else {

                //헤더 byte 를 체크
                FileInputStream inputStream = new FileInputStream(jpegTxt);
                byte[] headerBytes = new byte[10];
                int bytesRead = inputStream.read(headerBytes);

                String header = identifyImageFormat(headerBytes);
                this.setFileExt(header);

                if ("Unknown".equals(header)) {
                    System.out.println("Header: " + bytesToHex(headerBytes));
                    Alert alert = new Alert((Alert.AlertType.INFORMATION));
                    alert.setTitle("ERROR");
                    alert.setContentText(header+ "입니다. JPEG, BMP, PNG파일의 형식이어야 합니다");
                    alert.show();

                } else {

                    //암호 셋팅
                    this.setSecretKey(encryptionKey);

                    //docx 파일을 읽어들인다.
                    //FileInputStream fis = new FileInputStream(docxTxt);
                    //StringBuilder docxContent = readDocxWithStyle(fis);

                    //1. docx 파일을 읽어서 zip 압축한다.
                    byte[] docxContent = this.compressDocxToZip(docxTxt);

                    // 2. 압축한 byte 를 AES로 암호화
                    String docxBase64Bytes = encryptAES(docxContent);

                    //String docxBase64 = Base64.getEncoder().encodeToString(docxContent.getBytes(StandardCharsets.UTF_8));
                    // Base64 문자열을 byte 배열로 변환

                    int docxLen = docxBase64Bytes.length();

                    // JPEG 파일을 읽기 위한 FileInputStream 생성
                    FileInputStream fileInputStream = new FileInputStream(jpegTxt);

                    // JPEG 파일의 데이터를 ByteArrayOutputStream에 복사
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];

                    while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                        byteArrayOutputStream.write(buffer, 0, bytesRead);
                    }

                    // JPEG 파일 데이터를 byte 배열로 가져옴
                    byte[] jpegData = byteArrayOutputStream.toByteArray();
                    System.out.println("====jpegData==== : " + jpegData.toString());

                    // 변환한 Base64 데이터를 JPEG 데이터의 FF D9 시그니처 바로 전에, content << content length << FFD9 삽입
                    byte[] modifiedJpegData = insertDataAddLen(jpegData, docxBase64Bytes.getBytes());

                    System.out.println("====modifiedJpegData====");
                    System.out.println(modifiedJpegData.toString());

                    // 수정된 데이터로 JPEG 파일을 생성
                    String jpgFileResult = getResultFile(jpegTxt);
                    System.out.println("===jpgFileResult===");
                    System.out.println(jpgFileResult);
                    FileOutputStream fileOutputStream = new FileOutputStream(jpgFileResult);
                    fileOutputStream.write(modifiedJpegData);

                    // 스트림 닫기
                    fileInputStream.close();
                    fileOutputStream.close();

                    docxTextResult.setText("성공적으로 실행헀습니다.");
                    System.out.println("Base64 data inserted successfully.");
                    jpegResultTextField.setText(jpgFileResult);
                }
            }
        }

    }


    // JPEG 데이터의 FF D9 시그니처 바로 전에 데이터를 삽입하는 메서드
    private byte[] insertDataAddLen(byte[] jpegData, byte[] docxData) {
        // JPEG Footer : FF D9, 또는 PNG Footer : 49 45 4E 44 AE 42 60 82 시그니처의 위치를 찾음
        int signatureIndex = this.findSignatureIndex(jpegData);

        int docxDataLen = docxData.length;
        System.out.println("docxData.length : "+ docxData.length);

        byte[] lenByte = intToBytesUsingByteBuffer(docxDataLen);
        System.out.println("dataToInsertLen byte  value: " + lenByte.length);

        //원본 docx 데이터에 1024바이트(원본docx데이타길이)를 더해준다.
        byte[] docxMergedData = new byte[docxDataLen + docxBase64LenBuffer];
        System.arraycopy(docxData, 0, docxMergedData, 0, docxDataLen);
        System.arraycopy(lenByte, 0, docxMergedData, docxDataLen, lenByte.length);
        int docxMergedDataLen = docxMergedData.length;

        //System.arraycopy(src, srcPos, dest, destPos, length)
        // FF D9 시그니처 전까지의 데이터와 삽입할 데이터를 병합하여 새로운 byte 배열 생성
        byte[] modifiedData = new byte[jpegData.length + docxMergedData.length];

        System.arraycopy(jpegData, 0, modifiedData, 0, signatureIndex);

        System.arraycopy(docxMergedData, 0, modifiedData, signatureIndex, docxMergedDataLen);

        System.arraycopy(jpegData, signatureIndex, modifiedData, signatureIndex + docxMergedDataLen, jpegData.length - signatureIndex);

        return modifiedData;
    }


    // JPEG, PNG 데이터에서 footer 시그니처의 위치를 찾는 메서드
    private int findSignatureIndex(byte[] jpegData) {
        int signatureIndex = 0;

        if ("JPEG".equals(this.getFileExt())) {
            signatureIndex = jpegData.length - 2;

        } else if ("GIF".equals(this.getFileExt())) {
            signatureIndex = jpegData.length - 2;

        } else if ("PNG".equals(this.getFileExt())) {
            signatureIndex = jpegData.length - 8;

        } else if ("BMP".equals(this.getFileExt())) {
            signatureIndex = jpegData.length;
        }
        System.out.println("signatureIndex : "+ signatureIndex);

        return signatureIndex; // 시그니처를 찾지 못한 경우
    }


}