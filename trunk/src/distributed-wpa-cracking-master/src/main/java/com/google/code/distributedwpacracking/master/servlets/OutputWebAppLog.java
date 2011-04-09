package com.google.code.distributedwpacracking.master.servlets;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.google.code.distributedwpacracking.master.GlobalConstants;

public class OutputWebAppLog extends HttpServlet {
	private static final long serialVersionUID = 8155994140355448770L;
	
	@Override
	protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
		final org.apache.log4j.rolling.RollingFileAppender rollingAppender = (org.apache.log4j.rolling.RollingFileAppender) Logger.getRootLogger().getAppender("rolling");
		
		if(null == rollingAppender) {
			resp.sendError(HttpServletResponse.SC_NOT_FOUND, "No rolling log file is configured");
			return;
		}
		
		
		final File logFile = new File(rollingAppender.getFile());
		
		if(null == logFile || !logFile.exists()) {
			resp.sendError(HttpServletResponse.SC_NOT_FOUND, "No rolling log file exists");
			return;
		}
		
		
		final BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(logFile), GlobalConstants.UTF8));
		
		
		resp.setContentType("text/plain");
		resp.setCharacterEncoding(GlobalConstants.UTF8.displayName());
		resp.setStatus(HttpServletResponse.SC_OK);
		
		final PrintWriter writer = resp.getWriter();
		
		String cLine;
		while(null != (cLine = reader.readLine())) {
			writer.write(cLine);
			writer.write(System.getProperty("line.separator"));
		}
		
		reader.close();
		
	}
}
