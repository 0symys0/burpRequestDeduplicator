package burp;

import java.io.PrintWriter;
import java.lang.String;
import java.awt.Component;
import java.net.URL;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashSet;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IProxyListener, IMessageEditorController
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private final LinkedHashSet<LinkedHashSet<String>> requestsMemory = new LinkedHashSet<LinkedHashSet<String>>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IRequestInfo requestInfo;
    private IResponseInfo responseInfo;
    private IHttpService httpService;
    private URL currentURL;
    private int requestsIndex = 0;
    private List<IParameter> currentParamsList;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("Unique Parameter-URL Combos Logger");
        
        // create our UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                // main split pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                        
                // table of log entries
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, true);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, true);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);
                
                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
                
                // register ourselves as an HTTP listener
                callbacks.registerProxyListener(BurpExtender.this);
            }
        });
    }

    //
    // implement ITab
    //

    @Override
    public String getTabCaption()
    {
        return "RequestDeduplicator";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    //
    // implement IHttpListener
    //
    
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage interceptedMessage)
    {
        // only process responses
        if (!messageIsRequest)
        {
            IHttpRequestResponse messageInfo = interceptedMessage.getMessageInfo();
            requestInfo = helpers.analyzeRequest(messageInfo);
            byte[] rawResponse = messageInfo.getResponse();
            responseInfo = helpers.analyzeResponse(rawResponse);
            httpService = messageInfo.getHttpService();
            
            currentParamsList = requestInfo.getParameters();
            boolean paramsNotNull = (currentParamsList!=null);
            boolean paramsNotEmpty;
            if(paramsNotNull){
              paramsNotEmpty = !(currentParamsList.isEmpty());
            } else {
              paramsNotEmpty = false;
            }
            boolean requestWasEdited = (requestViewer.isMessageModified());
            boolean responseWasEdited = (responseViewer.isMessageModified());

            int responseLength;
            if(rawResponse!=null){
              responseLength = rawResponse.length;
            } else {
              responseLength = 0;
            }


            currentURL = requestInfo.getUrl();
            //strip everything after the '?' in order to strip off the parameters
            String withParamsURL = currentURL.toString();
            String URLString;
            int paramDelimiterIndex = withParamsURL.lastIndexOf("?");
            if (paramDelimiterIndex > 0) {
                URLString = withParamsURL.substring(0,withParamsURL.lastIndexOf("?"));
            } else {
                URLString = withParamsURL;
            }
            LinkedHashSet<String> URLParamSet = new LinkedHashSet<String>();
            URLParamSet.add(URLString);
            if(paramsNotNull){
                for(IParameter param : currentParamsList){
                  URLParamSet.add(param.getName());
                }
            }
            synchronized(requestsMemory)
            {
                boolean found = false;  
                for (LinkedHashSet<String> rememberedParamSet : requestsMemory) {
                  if(rememberedParamSet.containsAll(URLParamSet) && URLParamSet.containsAll(rememberedParamSet)) {
                    found = true;
                  }
                }
                if(!found){
                      requestsMemory.add(URLParamSet);
                      requestsIndex++;

                      // obtain our output and error streams
                      PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
                      PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
                      stderr.println("URL_PARAM_STRING_BEGIN:)");
                      stderr.println(URLParamSet);
                      stderr.println("URL_PARAM_STRING_END:)");
                      stderr.println("URLString_BEGIN");
                      stderr.println(URLString);
                      stderr.println("URLString_END:)");


                      byte[] rawRequest = messageInfo.getRequest();
                      stdout.println("REQUEST_BEGIN");
                      stdout.println(helpers.bytesToString(rawRequest));
                      stdout.println("REQUEST_END");

                      stdout.println("RESPONSE_BEGIN");
                      stdout.println(helpers.bytesToString(rawRequest));
                      stdout.println("RESPONSE_END");

                      // create a new log entry with the message details
                      synchronized(log)
                      {
                          int row = log.size();
                          log.add(new LogEntry(requestsIndex, callbacks.saveBuffersToTempFiles(messageInfo), 
                                currentURL, httpService.getHost(), requestInfo.getMethod(),paramsNotEmpty,(requestWasEdited || responseWasEdited),
                                responseInfo.getStatusCode(),responseLength,responseInfo.getInferredMimeType(), messageInfo.getComment(), httpService.getProtocol(),httpService.getPort()));
                          fireTableRowsInserted(row, row);
                      }
                }
            }
            

        }
    
    }


    //
    // extend AbstractTableModel
    //
    
    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 12;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "#";
            case 1:
                return "Host";
            case 2:
                return "Method";
            case 3:
                return "URL";
            case 4:
                return "Params";
            case 5:
                return "Edited";
            case 6:
                return "Status";
            case 7:
                return "Length";
            case 8:
                return "MIME type";
            case 9:
                return "Comment";
            case 10:
                return "Protocol";
            case 11:
                return "Service Port";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.logIndex;
            case 1:
                return logEntry.host;
            case 2:
                return logEntry.method;
            case 3:
                return logEntry.url.toString();
            case 4:
                return logEntry.hasParams;
            case 5:
                return logEntry.edited;
            case 6:
                return logEntry.status;
            case 7:
                return logEntry.length;
            case 8:
                return logEntry.mimeType;
            case 9:
                return logEntry.comment;
            case 10:
                return logEntry.protocol;
            case 11:
                return logEntry.port;
            default:
                return "";
        }
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //
    
    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //
    
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            
            super.changeSelection(row, col, toggle, extend);
        }        
    }
    
    //
    // class to hold details of each log entry
    //
    
    private static class LogEntry
    {
        final int logIndex;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;
        final String host;
        final String method;
        final boolean hasParams;
        final boolean edited;
        final short status;
        final int length;
        final String mimeType;
        final String comment;
        final String protocol;
        final int port;


        LogEntry(int logIndex, IHttpRequestResponsePersisted requestResponse, URL url, String host, String method, boolean hasParams,boolean edited, short status, int length, String mimeType, String comment, String protocol, int port)
        {
            this.logIndex = logIndex;
            this.requestResponse = requestResponse;
            this.url = url;
            this.host = host;
            this.method = method;
            this.hasParams = hasParams;
            this.edited = edited;
            this.status = status;
            this.length = length;
            this.mimeType = mimeType;
            this.comment = comment;
            this.protocol = protocol;
            this.port = port;
        }
    }
}
