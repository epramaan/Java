package com.example.demo;


import com.fasterxml.jackson.annotation.JsonCreator;

public class EnrolSPServiceResponseWrapper
{
    private String encryptedEnrolSPServiceResponse;
    private int serviceId;
    
    public String getEncryptedEnrolSPServiceResponse() {
        return this.encryptedEnrolSPServiceResponse;
    }
    
    public void setEncryptedEnrolSPServiceResponse(final String encryptedEnrolSPServiceResponse) {
        this.encryptedEnrolSPServiceResponse = encryptedEnrolSPServiceResponse;
    }
    
    public int getServiceId() {
        return this.serviceId;
    }
    
    public void setServiceId(final int serviceId) {
        this.serviceId = serviceId;
    }
    
    public EnrolSPServiceResponseWrapper(final String encryptedEnrolSPServiceResponse, final int serviceId) {
        this.encryptedEnrolSPServiceResponse = encryptedEnrolSPServiceResponse;
        this.serviceId = serviceId;
    }
    
    @Override
    public String toString() {
        return "EnrolSPServiceResponseWrapper [encryptedEnrolSPServiceResponse=" + this.encryptedEnrolSPServiceResponse + ", serviceId=" + this.serviceId + "]";
    }
    
    @JsonCreator
    public EnrolSPServiceResponseWrapper() {
    }
}