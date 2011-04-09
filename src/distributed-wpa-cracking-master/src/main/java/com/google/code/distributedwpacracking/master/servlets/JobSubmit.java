package com.google.code.distributedwpacracking.master.servlets;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.log4j.Logger;

import com.google.code.distributedwpacracking.master.GlobalConstants;
import com.google.code.distributedwpacracking.master.GlobalData;
import com.google.code.distributedwpacracking.master.Job;
import com.google.code.distributedwpacracking.master.WebAppConfig;
import com.google.code.distributedwpacracking.master.utils.StringUtils;

public class JobSubmit extends HttpServlet {
	private static final long serialVersionUID = 2110921015100918038L;

	private static final Logger log = Logger.getLogger(JobSubmit.class);
	
	@SuppressWarnings("unchecked")
	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		final String owner = req.getRemoteUser();
		

		/* Parse the multipart/form-data request into usable parameters */
		// Create a factory for disk-based file items
		final FileItemFactory factory = new DiskFileItemFactory();

		// Create a new file upload handler
		final ServletFileUpload upload = new ServletFileUpload(factory);
		
		final List<FileItem> multipartParameters;
		try {
			multipartParameters = upload.parseRequest(req);
		} catch (final FileUploadException e) {
			log.error(e,e);
			log.error("Upload request was by " + owner);
			resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unable to parse parameters because:  " + e.getMessage());
			return;
		}

		
		String ssid = null;
		FileItem wirelessCaptureUpload = null;

		
		for(final FileItem cFileItem : multipartParameters) {
			if(!cFileItem.isFormField() && "wireless_capture_file".equals(cFileItem.getFieldName())) {
				wirelessCaptureUpload = cFileItem;
			} else if(cFileItem.isFormField() && "ssid".equals(cFileItem.getFieldName())) {
				ssid = cFileItem.getString(GlobalConstants.UTF8.displayName());
			}
		}
		
		
		// IEEE spec doesn't specify allowed values other than 0-32 octets of data
		// We restrict allowed characters to avoid security attacks
		
		ssid = StringUtils.replaceAll(ssid, "[^\\x20-\\x7E]", "");  // only printable US ASCII
		
		if(StringUtils.isEmpty(ssid) || ssid.length() > 32) {
			// Invalid
			resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "ssid was of wrong length or empty");
			return;
		}
		
		if(null == wirelessCaptureUpload) {
			log.error("No file upload provided");
			resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "wireless_capture_file not given");
			return;
		}
		
		
		// Create the job so we can get an id for use
		final Job job = new Job(owner, ssid);
		
		
		// Save the capture file to disk
		final File jobDir = new File(WebAppConfig.getInstance().getJobOutputDirectory(), job.getId());
		jobDir.mkdirs();
		
		final File captureFile = new File(jobDir, "WIRELESS_CAPTURE");  // don't use user specified name to avoid security attacks
		
		try {
			wirelessCaptureUpload.write(captureFile);
		} catch (final Exception e) {
			log.error("Failed to save file upload to disk for owner " + owner, e);
			log.debug(captureFile.getAbsoluteFile());
			log.debug(wirelessCaptureUpload.getSize() + " bytes");
			log.debug(wirelessCaptureUpload.getContentType());
			resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
			return;
		}
		
		// Save the SSID information to disk too
		final File ssidInfoFile = new File(jobDir, "SSID.txt");
		final OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(ssidInfoFile), GlobalConstants.UTF8);
		osw.write(ssid);
		osw.close();
		
		
		log.info("Added job with id " + job.getId() + " and owner " + job.getOwner());
		GlobalData.getInstance().enqueueJob(job);
		
		req.getSession().setAttribute("StatusMessage", "Added new job to queue");
		resp.sendRedirect(resp.encodeRedirectURL(getServletContext().getContextPath() + "/welcome.jspx"));
	}
}
