<?xml version='1.0' ?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="StandardTransforms.xsl"/>

  <xsl:output method="xml" omit-xml-declaration="no"/>

  <xsl:template match="/"> 
	<xsl:element name="StorageNodes">
	    <xsl:apply-templates select="CurrentDirectory"/>
	</xsl:element>
  </xsl:template>

  <xsl:template match="CurrentDirectory">
    <xsl:element name="Storage">
      <xsl:attribute name="type">string</xsl:attribute>
      <xsl:attribute name="name">path</xsl:attribute>
      <xsl:attribute name="value"><xsl:value-of select="."/></xsl:attribute>
    </xsl:element>

    <!-- also record as "string_val" for backwards compatiblity -->
    <xsl:element name="Storage">
      <xsl:attribute name="type">string</xsl:attribute>
      <xsl:attribute name="name">string_val</xsl:attribute>
      <xsl:attribute name="value"><xsl:value-of select="."/></xsl:attribute>
    </xsl:element>

  </xsl:template>

</xsl:transform>