package com.example.digital_signature_demo.service;

import java.util.Base64;
import java.util.zip.GZIPOutputStream;
import java.util.zip.GZIPInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.HashMap;
import java.util.Map;
import java.io.IOException;
import java.security.Security;
import java.awt.image.BufferedImage;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.example.digital_signature_demo.model.Document;
import com.example.digital_signature_demo.repository.DocumentRepository;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.provider.DilithiumProvider;
import net.thiim.dilithium.impl.PackingUtils;
import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;
import com.example.digital_signature_demo.model.User;
@Service
public class DocumentService {

    private static final Logger logger = LoggerFactory.getLogger(DocumentService.class);

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private UserService userService;

    static {
        Security.addProvider(new DilithiumProvider());
    }
    public byte[] signDocument(byte[] documentContent, User user) {
        try {
            byte[] privateKeyBytes = userService.getPrivateKeyFromUSB(user.getUsername());
            byte[] publicKeyBytes = userService.getPublicKeyFromUSB(user.getUsername());
            DilithiumPrivateKey privateKey = (DilithiumPrivateKey) PackingUtils.unpackPrivateKey(DilithiumParameterSpec.LEVEL3, privateKeyBytes);
            DilithiumPublicKey publicKey = (DilithiumPublicKey) PackingUtils.unpackPublicKey(DilithiumParameterSpec.LEVEL3, publicKeyBytes);

            // Chuyển đổi khóa công khai thành chuỗi để lưu vào mã QR
            String publicKeyStr = Base64.getEncoder().encodeToString(userService.getPublicKeyFromUSB(user.getUsername()));

            // Tạo một tài liệu mới để lưu thông tin ký
            Document document = new Document();
            document.setUser(user);
            document.setSignDate(new Date());
            documentRepository.save(document);

            // Chuyển đổi ID tài liệu thành chuỗi để lưu vào mã QR
            String documentIdStr = Base64.getEncoder().encodeToString(document.getId().toString().getBytes());

            // Tạo chuỗi mã QR chứa cả khóa công khai và ID tài liệu
            String qrContent = "PublicKey:" + publicKeyStr + ";DocumentID:" + documentIdStr;

            // Tạo mã QR với mức sửa lỗi thấp để tăng khả năng lưu trữ
            ByteArrayOutputStream qrOutputStream = new ByteArrayOutputStream();
            generateQRCodeImage(qrContent, 250, 250, qrOutputStream, ErrorCorrectionLevel.L); 
            byte[] qrImage = qrOutputStream.toByteArray();

            // Tạo tệp PDF với mã QR
            PDDocument pdfDocument = PDDocument.load(documentContent);
            PDPage lastPage = pdfDocument.getPage(pdfDocument.getNumberOfPages() - 1);
            PDPageContentStream contentStream = new PDPageContentStream(pdfDocument, lastPage, PDPageContentStream.AppendMode.APPEND, true, true);

            // Viết mã QR vào trang cuối của tài liệu PDF
            PDImageXObject pdImage = PDImageXObject.createFromByteArray(pdfDocument, qrImage, "QR");
            contentStream.drawImage(pdImage, 5, 5, 200, 200); 
            contentStream.close();

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            pdfDocument.save(outputStream);
            pdfDocument.close();

            byte[] pdfWithQR = outputStream.toByteArray();
            // Ký tài liệu PDF đã có mã QR
            byte[] signature = Dilithium.sign(privateKey, pdfWithQR);
            document.setSignature(signature);
            document.setSignedDocumentContent(pdfWithQR);
            documentRepository.save(document);

            return pdfWithQR;
        } catch (Exception e) {
            logger.error("Lỗi khi ký tài liệu", e);
            throw new RuntimeException("Lỗi khi ký tài liệu", e);
        }
    }

    public void generateQRCodeImage(String text, int width, int height, ByteArrayOutputStream outputStream, 
    ErrorCorrectionLevel errorCorrectionLevel) throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
        hints.put(EncodeHintType.ERROR_CORRECTION, errorCorrectionLevel);
        hints.put(EncodeHintType.MARGIN, 0);
        hints.put(EncodeHintType.QR_VERSION, 40);

        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height, hints);
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
    }

    public Map<String, Object> verifyDocument(byte[] signedDocumentContent) {
        try {
            // Đọc nội dung PDF và mã QR để lấy khóa công khai và ID tài liệu
            PDDocument pdfDocument = PDDocument.load(signedDocumentContent);
            String qrContent = extractQRCodeContentFromLastPage(pdfDocument);
            pdfDocument.close();

            // Phân tích nội dung QR để lấy khóa công khai và ID tài liệu
            String[] parts = qrContent.split(";");
            String publicKeyStr = parts[0].split(":")[1];
            String documentIdStr = new String(Base64.getDecoder().decode(parts[1].split(":")[1]));

            // Giải mã khóa công khai từ chuỗi
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            DilithiumPublicKey publicKey = (DilithiumPublicKey) PackingUtils.unpackPublicKey(DilithiumParameterSpec.LEVEL3, publicKeyBytes);

            // Lấy tài liệu từ cơ sở dữ liệu bằng ID tài liệu
            Long documentId = Long.parseLong(documentIdStr);
            Document document = documentRepository.findById(documentId)
                    .orElseThrow(() -> new RuntimeException("Không tìm thấy tài liệu"));

            // Xác thực nội dung tài liệu đã ký
            boolean isVerified = Dilithium.verify(publicKey, document.getSignature(), document.getSignedDocumentContent());
            Map<String, Object> result = new HashMap<>();
            result.put("isVerified", isVerified);
            if (isVerified) {
                result.put("signDate", document.getSignDate());
                result.put("signedBy", document.getUser().getUsername());
                logger.info("Tài liệu được xác thực thành công.");
            } else {
                result.put("message", "Xác thực tài liệu thất bại.");
                logger.warn("Xác thực tài liệu thất bại.");
            }
            return result;
        } catch (Exception e) {
            logger.error("Lỗi khi xác thực tài liệu", e);
            throw new RuntimeException("Lỗi khi xác thực tài liệu", e);
        }
    }

    private String extractQRCodeContentFromLastPage(PDDocument document) throws IOException, NotFoundException {
        int lastPageIndex = document.getNumberOfPages() - 1;
        PDFRenderer pdfRenderer = new PDFRenderer(document);
        BufferedImage bim = pdfRenderer.renderImageWithDPI(lastPageIndex, 300, ImageType.RGB);

        LuminanceSource source = new BufferedImageLuminanceSource(bim);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        Result result = new MultiFormatReader().decode(bitmap);

        return result.getText();
    }


    public List<Document> getAllSignedDocuments() {
        return documentRepository.findAll();
    }

    public Optional<Document> getDocumentById(Long id) {
        return documentRepository.findById(id);
    }

}
