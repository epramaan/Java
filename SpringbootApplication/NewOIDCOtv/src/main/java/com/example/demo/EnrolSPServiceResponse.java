package com.example.demo;

import com.fasterxml.jackson.annotation.JsonCreator;
import java.util.UUID;
import java.io.Serializable;

public class EnrolSPServiceResponse implements Serializable
{
    private static final long serialVersionUID = 1L;
    private UUID transactionId;
    private String serviceUserId;
    private boolean verified;
    private long responseTimestamp;
    private int serviceId;
    
    @JsonCreator
    public EnrolSPServiceResponse() {
    }
    
    public EnrolSPServiceResponse(final UUID transactionId, final String serviceUserId, final boolean verified, final long responseTimestamp, final int serviceId) {
        this.transactionId = transactionId;
        this.serviceUserId = serviceUserId;
        this.verified = verified;
        this.responseTimestamp = responseTimestamp;
        this.serviceId = serviceId;
    }
    
    public int getServiceId() {
        return this.serviceId;
    }
    
    public void setServiceId(final int serviceId) {
        this.serviceId = serviceId;
    }
    
    public long getResponseTimestamp() {
        return this.responseTimestamp;
    }
    
    public void setResponseTimestamp(final long responseTimestamp) {
        this.responseTimestamp = responseTimestamp;
    }
    
    public UUID getTransactionId() {
        return this.transactionId;
    }
    
    public void setTransactionId(final UUID transactionId) {
        this.transactionId = transactionId;
    }
    
    public String getServiceUserId() {
        return this.serviceUserId;
    }
    
    public void setServiceUserId(final String serviceUserId) {
        this.serviceUserId = serviceUserId;
    }
    
    public boolean isVerified() {
        return this.verified;
    }
    
    public void setVerified(final boolean verified) {
        this.verified = verified;
    }
    
    @Override
    public String toString() {
        return "EnrolSPServiceResponse [transactionId=" + this.transactionId + ", serviceUserId=" + this.serviceUserId + ", verified=" + this.verified + ", responseTimestamp=" + this.responseTimestamp + "]";
    }
}