package com.example.urbanvoyagebackend.service.travel;

import com.adobe.pdfservices.operation.ExecutionContext;
import com.adobe.pdfservices.operation.auth.Credentials;
import com.adobe.pdfservices.operation.io.FileRef;
import com.adobe.pdfservices.operation.pdfops.CreatePDFOperation;
import com.adobe.pdfservices.operation.pdfops.options.createpdf.CreatePDFOptions;
import com.example.urbanvoyagebackend.entity.travel.Passenger;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class TicketService {

    private static final Logger logger = LoggerFactory.getLogger(TicketService.class);

    @Value("${adobe.pdf.clientId}")
    private String clientId;

    @Value("${adobe.pdf.clientSecret}")
    private String clientSecret;

    public byte[] generateTicket(Reservation reservation, Passenger passenger) throws IOException {
        Path tempHtmlPath = null;
        Path tempPdfPath = null;
        ByteArrayOutputStream pdfOutputStream = null;

        try {
            // Set up the PDF Services SDK
            Credentials credentials = Credentials.servicePrincipalCredentialsBuilder()
                    .withClientId(clientId)
                    .withClientSecret(clientSecret)
                    .build();

            ExecutionContext executionContext = ExecutionContext.create(credentials);

            // Create HTML content for the ticket, including the QR code
            String htmlContent = createTicketHTML(reservation, passenger);

            // Save HTML content to a temporary file
            tempHtmlPath = Files.createTempFile("ticket_html_", ".html");
            Files.write(tempHtmlPath, htmlContent.getBytes());

            // Set up the PDF creation operation
            CreatePDFOperation createPDFOperation = CreatePDFOperation.createNew();

            // Create FileRef from the temporary HTML file
            FileRef source = FileRef.createFromLocalFile(tempHtmlPath.toString());
            createPDFOperation.setInput(source);

            // Set options for PDF creation
            CreatePDFOptions options = CreatePDFOptions.htmlOptionsBuilder()
                    .includeHeaderFooter(true)
                    .build();
            createPDFOperation.setOptions(options);

            // Generate the PDF
            FileRef result = createPDFOperation.execute(executionContext);

            // Generate a unique filename for the PDF
            String uniqueFileName = "ticket_pdf_" + System.currentTimeMillis() + "_" + reservation.getReservationID() + ".pdf";
            Path finalPdfPath = Path.of("/tmp", uniqueFileName);

            // Save the PDF to the unique file
            result.saveAs(finalPdfPath.toString());

            // Read the PDF file into a byte array
            byte[] pdfBytes = Files.readAllBytes(finalPdfPath);

            // Optionally, save to ByteArrayOutputStream for further processing if needed
            pdfOutputStream = new ByteArrayOutputStream();
            pdfOutputStream.write(pdfBytes);

            return pdfBytes;
        } catch (Exception e) {
            logger.error("Failed to generate ticket PDF", e);
            throw new IOException("Failed to generate ticket PDF: " + e.getMessage(), e);
        } finally {
            // Clean up temporary files
            cleanupTempFile(tempHtmlPath);
            cleanupTempFile(tempPdfPath);
            closeQuietly(pdfOutputStream);
        }
    }

    private String createTicketHTML(Reservation reservation, Passenger passenger) throws Exception {
        // Generate QR code
        String qrCodeImage = generateQRCodeImage(passenger.getSerialNumber());

        // Format dates
        DateTimeFormatter inputFormatter = DateTimeFormatter.ISO_DATE_TIME;
        String formattedDepartureTime = formatDateTime(passenger.getDepartureTime(), inputFormatter);
        String formattedArrivalTime = formatDateTime(passenger.getArrivalTime(), inputFormatter);


        // Create an HTML string with ticket details and QR code
        return "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>UrbanVoyage Boarding Pass</title>" +
                "<style>" +
                "@import url('https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,300;0,400;0,500;0,700;1,300;1,400;1,500;1,700&display=swap');" +
                "* { font-family: \"Ubuntu\", sans-serif; margin: 0; padding: 0; box-sizing: border-box; }" +
                "body, html { height: 100%; width: 100%; overflow: hidden; }" +
                "body { background-color: white; display: flex; justify-content: center; align-items: center; border-radius:20px; }" +
                ".ticket { width: 100%; height: 100%; background-color: white; }" +
                ".ticket-header { background-color: #06b6d4; color: white; padding: 20px 32px; text-align: center; position: relative; }" +
                ".ticket-header::before { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background-image: url('https://media.istockphoto.com/id/842924980/photo/abstract-soap-foam-bubbles.webp?s=2048x2048&w=is&k=20&c=-742_N7U3ehoUfd3-oeIe0cIRlZabGbCjHxd3QX_RCk='); background-size: cover; opacity: 0.5; z-index: 0; }" +
                ".ticket-header > * { position: relative; z-index: 1; }" +
                ".app-title { font-size: 48px; font-weight: bold; margin-bottom: 10px; }" +
                ".thank-you { font-size: 18px; opacity: 0.9; }" +
                ".ticket-content { padding: 32px; }" +
                ".boarding-pass-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }" +
                ".boarding-pass { font-size: 28px; font-weight: bold; color: #333; }" +
                ".ticket-status { background-color: #06b6d4; color: white; padding: 6px 14px; border-radius: 20px; font-size: 16px; font-weight: 500; }" +
                ".ticket-details { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 30px; }" +
                ".detail-item { margin-bottom: 20px; }" +
                ".detail-label { font-size: 14px; color: #666; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }" +
                ".detail-value { font-size: 18px; font-weight: 500; color: #333; }" +
                ".detail-value-italic { font-size: 18px; font-weight: 600; color:#06b6d4;font-style: italic; }" +
                ".qr-code { text-align: center; }" +
                ".qr-code img { border-radius: 8px; width: 200px; height: 200px; }" +
                ".footer { text-align: center; margin-top: 30px; font-size: 14px; color: #666; }" +
                "</style></head><body>" +
                "<div class=\"ticket\">" +
                "<div class=\"ticket-header\">" +
                "<div class=\"app-title\">UrbanVoyage</div>" +
                "<div class=\"thank-you\">Thank you for choosing UrbanVoyage. Enjoy your journey!</div>" +
                "</div>" +
                "<div class=\"ticket-content\">" +
                "<div class=\"boarding-pass-row\">" +
                "<div class=\"boarding-pass\">Boarding Pass</div>" +
                "<div class=\"ticket-status\">Confirmed</div>" +
                "</div>" +
                "<div class=\"ticket-details\">" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">Passenger</div>" +
                "<div class=\"detail-value\">" + passenger.getFirstName() + " " + passenger.getLastName() + "</div>" +
                "</div>" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">Reservation ID</div>" +
                "<div class=\"detail-value\">" + reservation.getReservationID() + "</div>" +
                "</div>" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">From</div>" +
                "<div class=\"detail-value\">" + passenger.getDepartureCity() + "</div>" +
                "</div>" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">To</div>" +
                "<div class=\"detail-value\">" + passenger.getArrivalCity() + "</div>" +
                "</div>" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">Departure</div>" +
                "<div class=\"detail-value\">" + formattedDepartureTime + "</div>" +
                "</div>" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">Arrival</div>" +
                "<div class=\"detail-value\">" + formattedArrivalTime + "</div>" +
                "</div>" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">Seat Type</div>" +
                "<div class=\"detail-value-italic\">" + passenger.getSeatType() + "</div>" +
                "</div>" +
                "<div class=\"detail-item\">" +
                "<div class=\"detail-label\">Price</div>" +
                "<div class=\"detail-value\">" + passenger.getSchedulePrice() + "MAD </div>" +
                "</div>" +
                "</div>" +
                "<div class=\"qr-code\">" +
                "<img src=\"data:image/png;base64," + qrCodeImage + "\" alt=\"QR Code\" />" +
                "</div>" +
                "<div class=\"footer\">This boarding pass is your ticket to travel. Please present it along with a valid ID at the boarding gate.</div>" +
                "</div>" +
                "</div>" +
                "</body></html>";
    }

    private String formatDateTime(Object dateTime, DateTimeFormatter inputFormatter) {
        DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("yyyy/MM/dd - HH'h'mm'min'");

        if (dateTime instanceof String) {
            // Parse the string to ZonedDateTime, then format to desired output
            ZonedDateTime zonedDateTime = ZonedDateTime.parse((String) dateTime, inputFormatter);
            return zonedDateTime.format(outputFormatter);
        } else if (dateTime instanceof ZonedDateTime) {
            return ((ZonedDateTime) dateTime).format(outputFormatter);
        } else {
            return "Invalid Date Format";
        }
    }
    private String generateQRCodeImage(String content) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, 200, 200);

        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
        byte[] pngData = pngOutputStream.toByteArray();
        return DatatypeConverter.printBase64Binary(pngData);
    }

    private void cleanupTempFile(Path tempFilePath) {
        if (tempFilePath != null) {
            try {
                Files.deleteIfExists(tempFilePath);
            } catch (IOException e) {
                logger.warn("Failed to delete temporary file: " + tempFilePath, e);
            }
        }
    }

    private void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                logger.warn("Failed to close resource", e);
            }
        }
    }
}