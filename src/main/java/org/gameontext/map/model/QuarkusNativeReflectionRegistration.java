package org.gameontext.map.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection(ignoreNested = false, classNames = {"org.ektorp.impl.QueryResultParser", "org.ektorp.ComplexKey"})
public class QuarkusNativeReflectionRegistration {
    
}