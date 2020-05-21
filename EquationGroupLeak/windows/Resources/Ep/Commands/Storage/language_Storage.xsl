<?xml version='1.0' ?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="StandardTransforms.xsl"/>

  <xsl:output method="xml" omit-xml-declaration="no"/>

  <xsl:template match="/"> 
	<xsl:element name="StorageNodes">
	    <xsl:apply-templates select="Language"/>
	</xsl:element>
  </xsl:template>

  <xsl:template match="Language">
    <xsl:element name="Storage">
      <xsl:attribute name="type">string</xsl:attribute>
      <xsl:attribute name="name">language_name</xsl:attribute>
      <xsl:attribute name="value"><xsl:value-of select="@name"/></xsl:attribute>
    </xsl:element>
    <xsl:element name="Storage">
      <xsl:attribute name="type">string</xsl:attribute>
      <xsl:attribute name="name">language_id</xsl:attribute>
      <xsl:attribute name="value"><xsl:value-of select="@id"/></xsl:attribute>
    </xsl:element>
  </xsl:template>

</xsl:transform>