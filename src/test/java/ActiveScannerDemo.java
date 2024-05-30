import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.zaproxy.clientapi.core.*;

import java.io.File;
import java.io.IOException;

public class ActiveScannerDemo {

    private static final String ZAP_PROXY_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8092;
    private static final String ZAP_API_KEY = "oi8e7aoqubmt8d361vok1tegsm";
    private static final String REPORT_DIR_NAME = "target";
    private static final String TARGET_SITE = "https://demo.testfire.net/login.jsp";
    private static final String ZAPJARNAME = "zap-api-1.13.0.jar";

    private WebDriver driver;
    private ClientApi clientApi;
    private static ApiResponse apiResponse;

    @BeforeClass
    public void setUp() throws IOException {
// Open the ZAp exe .
        launchZapJarFile(ZAPJARNAME);
        // Start ZAP proxy after that.
        // Path to zap .bat  file.
        String zapPath = "ZAP_2.14.0";
        startZapProxy(zapPath);
    }


    @Test
    public void activeScanDemo() throws ClientApiException, InterruptedException {
        // Create ZAP API client
        clientApi = new ClientApi(ZAP_PROXY_ADDRESS, ZAP_PORT, ZAP_API_KEY);

        // Create new session
        try {
            apiResponse = clientApi.core.newSession("OWASPZAPTest", "true");
        } catch (ClientApiException e) {
            e.printStackTrace();
        }
        // Set target site
        apiResponse = clientApi.core.accessUrl(TARGET_SITE, "true");
        // Wait for target site to load
        pause(3000);
        // Launch Firefox driver
        driver = setUpChromeDriver();
        // Set Firefox proxy to ZAP
        String proxy = ZAP_PROXY_ADDRESS + ":" + ZAP_PORT;
        org.openqa.selenium.Proxy seleniumProxy = new org.openqa.selenium.Proxy();
        seleniumProxy.setHttpProxy(proxy).setFtpProxy(proxy).setSslProxy(proxy);
        // Access target site and scan vulnerabilities in login page.
        driver.get(TARGET_SITE);
        // Wait for target site to load
        pause(15000);

        // Spider target site
        ApiResponse spiderResponse = scanSite(TARGET_SITE, "spider");
        System.out.println("spiderResponse--"+spiderResponse);

        // Active scan target site
        ApiResponse activeScanResponse = scanSite(TARGET_SITE, "active");
        System.out.println("activeScanResponse--"+activeScanResponse);



    }
    private ApiResponse scanSite(String site, String scanType) throws ClientApiException, InterruptedException {
        // Spider or active scan target site
        ApiResponse scanResponse = null;
        if (scanType.equals("spider")) {
            // Spider scanning is a process that automatically explores a website's structure and maps all its pages and links.
            scanResponse = clientApi.spider.scan(site, null, null, null, null);
        } else if (scanType.equals("active")) {
            // Active scanning involves sending malicious requests to the website and analyzing the response to detect potential vulnerabilities
            scanResponse = clientApi.ascan.scan(site, "True", "False", null, null, null);
        }

        // Wait for scan to finish
        int progress;
        String scanId = null;
        do {
            pause(1000);
            ApiResponseList scanResults = (ApiResponseList) clientApi.spider.results(scanId);
            if (scanId == null && scanResults.getItems().size() > 0) {
                scanId = ((ApiResponseElement) scanResults.getItems().get(0)).getValue();
            }
            progress = Integer.parseInt(((ApiResponseElement) clientApi.spider.status(scanId)).getValue());
            System.out.println(scanType + " progress: " + progress + "%");
        } while (progress < 100);

        System.out.println(scanType + " scan completed!");

        return scanResponse;
    }

    private static void startZapProxy(String zapPath) throws IOException {
        //ProcessBuilder is a class in the java.lang.ProcessBuilder package that allows you to create and control new processes in Java.
        Runtime.getRuntime().exec("cmd /c start zap.bat -daemon",null,new File(zapPath));

        pause(50000);// wait around 1 minute..
        /*
        This line starts the ZAP proxy process by calling the start() method on the processBuilder object.
        This launches the ZAP proxy process and returns a new Process object that represents the running process.
        By calling this method, you can launch the ZAP proxy process from within your Java code, which allows you to automate the process of starting and stopping the proxy, and integrate the proxy into your testing or security scanning workflows.
         */

    }

    public WebDriver setUpChromeDriver(){
        ChromeOptions options = new ChromeOptions();
        Proxy proxy = new Proxy();
        String proxyServerUrl = ZAP_PROXY_ADDRESS+":"+ZAP_PORT;
        proxy.setHttpProxy(proxyServerUrl);
        proxy.setSslProxy(proxyServerUrl);
        options.setProxy(proxy);
        options.setAcceptInsecureCerts(true);
        System.setProperty("webdriver.chrome.driver","chromedriver.exe");
        return new ChromeDriver(options);
    }

    private static void pause(int pause) {
        try {
            Thread.sleep(pause);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
    private static void launchZapJarFile(String zapJar) throws IOException {
// Before start proxy , it's a must to launch the ZAP application exe first.
//ProcessBuilder is a class in the java.lang.ProcessBuilder package that allows you to create and control new processes in Java.
        ProcessBuilder processBuilder = new ProcessBuilder("java", "-jar", zapJar);
        processBuilder.start();
        pause(15000);
 /*
This line starts the ZAP proxy process by calling the start() method on the processBuilder object.
This launches the ZAP proxy process and returns a new Process object that represents the running process.
By calling this method, you can launch the ZAP proxy process from within your Java code, which allows you to automate the process of starting and stopping the proxy, and integrate the proxy into your testing or security scanning workflows.
*/
// After that only startZapProxy should be called.
        System.out.println("ZAP exe is started.");

    }


    public void generateZapReport(String URLS) {
        String title = "Demo Passive report Title";
        String template = "traditional-html";
        String theme = null;
        String description = "Report description";
        String contexts = null;
        String sites = URLS;
        String sections = null;
        String includedconfidences = null;
        String includedrisks = null;
        String reportFileName = "ActiveScanHtmlReport";
        String reportfilenamepattern = null;
        String reportDirectory = System.getProperty("user.dir") + File.separator + REPORT_DIR_NAME;
        String display = null;

        try {
            clientApi.reports.generate(title, template, null, description, null, sites, null,
                    null, null, reportFileName, null, reportDirectory, null);
        } catch (ClientApiException e) {
            e.printStackTrace();
        }
    }

    @AfterClass
    public void tearDown() {
        generateZapReport(TARGET_SITE);
        driver.quit();
    }

}