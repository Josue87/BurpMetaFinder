package burp;


// Library https://pdfbox.apache.org/
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
// Library https://jar-download.com/artifacts/org.apache.poi/poi-ooxml
import org.apache.poi.ooxml.POIXMLProperties;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackageAccess;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.ArrayList;
import java.util.List;


public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("MetaFinder");
        callbacks.registerScannerCheck(this);
    }

    private boolean isDocument(String url_str) {
        return url_str.endsWith(".pdf") || url_str.endsWith(".docx") || url_str.endsWith(".xlsx") || url_str.endsWith(".pptx");
    }


    private  String downloadFile(String url_str) {
        URL website = null;
        String[] fileNameArray = url_str.split("/");
        String outputFileName = fileNameArray[fileNameArray.length-1];

        try {
            website = new URL(url_str);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return null;
        }
        try(InputStream in = website.openStream();
            ReadableByteChannel rbc = Channels.newChannel(in);
            FileOutputStream fos = new FileOutputStream(outputFileName))
        {
            fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return outputFileName;
    }

    private String docxMetadata(String fileName) {
        File myFile = new File(fileName);
        String data = "";
        try (OPCPackage pkg = OPCPackage.open(myFile, PackageAccess.READ_WRITE)) {
            boolean someData = false;
            POIXMLProperties props = new POIXMLProperties(pkg);
            POIXMLProperties.CoreProperties coreProps = props.getCoreProperties();

            String revision = coreProps.getRevision();
            String creator = coreProps.getCreator();
            String title = coreProps.getTitle();
            String identifier = coreProps.getIdentifier();
            String keywords = coreProps.getKeywords();
            String subject = coreProps.getSubject();
            String description = coreProps.getDescription();

            data += "<ul>";

            if (title != null){
                data += "<li>Title: " + title + "</li>";
                someData = true;
            }
            if (creator != null) {
                data += "<li>Author: " + creator + "</li>";
                someData = true;
            }
            if (subject != null) {
                data += "<li>Subject: " + subject + "</li>";
                someData = true;
            }
            if (description != null){
                data += "<li>Description: " + description + "</li>";
                someData = true;
            }
            if (keywords != null){
                data += "<li>Keywords: " + keywords + "</li>";
                someData = true;
            }
            if (identifier != null){
                data += "<li>Identifier: " + identifier + "</li>";
                someData = true;
            }
            if (revision != null){
                data += "<li>Revision: " + revision + "</li>";
                someData = true;
            }

            data += "</ul>";
            if (!someData){
                data = null;
            }
            pkg.flush();
            myFile.delete();
        } catch (Exception e) {
            return null;
        }

        return data;
    }

    private String pdfMetadata(String fileName) {
        PDDocument doc = null;
        String data = "<ul>";
        try {
            File myFile = new File(fileName);
            doc = PDDocument.load(myFile);
            PDDocumentInformation info = doc.getDocumentInformation();
            boolean someData = false;
            if (info.getTitle() != null){
                data += "<li>Title: " + info.getTitle()+ "</li>";
                someData = true;
            }
            if (info.getAuthor() != null){
                data += "<li>Author: " + info.getAuthor() + "</li>";
                someData = true;
            }
            if (info.getCreator() != null){
                data += "<li>Creator: " + info.getCreator() + "</li>";
                someData = true;
            }
            if (info.getSubject()!= null){
                data += "<li>Subject: " + info.getSubject()  + "</li>";
                someData = true;
            }
            if (info.getKeywords()!= null){
                data += "<li>Keywords: " + info.getKeywords() + "</li>";
                someData = true;
            }
            if (info.getProducer() != null){
                data += "<li>Producer: " + info.getProducer() + "</li>";
                someData = true;
            }
            data += "</ul>";
            if (!someData){
                data = null;
            }
            myFile.delete();

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return data;
    }

    private String getMetaData(String fileName) {
        if (fileName.endsWith("pdf")) {
            return pdfMetadata(fileName);
        } else { // docx, xlsx or pptx
            return docxMetadata(fileName);
        }
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        String url_str = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
        if (isDocument(url_str)){
            if (downloadFile(url_str) != null) {
                String[] fileNameArray = url_str.split("/");
                String fileName = fileNameArray[fileNameArray.length-1];
                String metadata = getMetaData(fileName);
                if (metadata != null) {
                    List<IScanIssue> issues = new ArrayList<>(1);
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, null)},
                            "Metadata Info Leakage",
                            "<p>Metadata found in file: " + fileName + "</p>" + metadata,
                            "Information"));
                    return issues;
                }
            }
        }

        return null;

    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse response,IScannerInsertionPoint intertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}


class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}